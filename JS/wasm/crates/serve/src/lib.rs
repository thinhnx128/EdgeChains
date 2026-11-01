use wit::arakoo::edgechains::http as outbound_http;
use wit::arakoo::edgechains::http_types::HttpError;

mod binding;
mod io;

use std::{
    collections::HashMap,
    convert::Infallible,
    env,
    future::Future,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    str::FromStr,
    task::{self, Poll},
};

use anyhow::Context;
use futures::future::{self, Ready};
use hyper::{
    body::HttpBody,
    header::{HeaderName, HeaderValue, CONTENT_LENGTH},
    http::request::Parts,
    server::conn::AddrStream,
    service::Service,
    Body, Request, Response, StatusCode,
};

use tracing::{error, event, info, Level};
use tracing_subscriber::{filter::EnvFilter, FmtSubscriber};
use wasmtime_wasi::{bindings, ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store, WasmBacktraceDetails};
use wit::arakoo::edgechains::http_types;
use wit::arakoo::edgechains::utils;
use wit::exports::arakoo::edgechains::inbound_http::{self};

use crate::io::{WasmInput, WasmOutput};

/// Maximum allowed inbound HTTP request body size (10 MiB) to prevent OOM DoS (CWE-400).
pub const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;

mod wit {
    wasmtime::component::bindgen!({
        path:"../../wit",
        world:"reactor",
        async:true
    });
}

#[derive(Clone)]
pub struct RequestService {
    worker_ctx: WorkerCtx,
}

impl RequestService {
    /// Create a new request service.
    fn new(ctx: WorkerCtx) -> Self {
        Self { worker_ctx: ctx }
    }
}

#[derive(Clone)]
pub struct WorkerCtx {
    engine: Engine,
    component: Component,
}

struct Host {
    table: ResourceTable,
    wasi: WasiCtx,
    client: Option<reqwest::Client>,
}

impl WasiView for Host {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }

    fn ctx(&mut self) -> &mut wasmtime_wasi::WasiCtx {
        &mut self.wasi
    }
}

impl http_types::Host for Host {}

impl WorkerCtx {
    pub fn new(component_path: impl AsRef<Path>) -> anyhow::Result<Self> {
        tracing_subscriber();
        info!("Loading Component from {:?}", component_path.as_ref());
        let mut binding = Config::default();
        let config = binding.async_support(true).wasm_component_model(true);
        if env::var("DEBUG").is_ok() {
            config
                .debug_info(true)
                .wasm_backtrace(true)
                .coredump_on_trap(true)
                .wasm_backtrace_details(WasmBacktraceDetails::Enable);
        }

        let engine = Engine::new(&config)?;
        let component = Component::from_file(&engine, component_path)
            .with_context(|| "Failed to load component : invalid path".to_string())?;

        Ok(Self { engine, component })
    }

    pub fn component(&self) -> &Component {
        &self.component
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    pub async fn serve(self, addr: SocketAddr) -> Result<(), hyper::Error> {
        info!("Starting server ...");
        let server = hyper::Server::bind(&addr).serve(self);
        event!(Level::INFO, "Listening on http://{}", server.local_addr());
        server.await?;
        Ok(())
    }

    pub async fn handle_request(
        &self,
        request: hyper::Request<hyper::Body>,
    ) -> anyhow::Result<(Response<Body>, Option<anyhow::Error>)> {
        let (parts, mut body) = request.into_parts();
        info!("Handling request: {:?} {:?}", parts.method, parts.uri);

        if let Some(cl_val) = parts.headers.get(CONTENT_LENGTH) {
            if let Ok(cl_str) = cl_val.to_str() {
                if let Ok(cl_len) = cl_str.parse::<usize>() {
                    if cl_len > MAX_REQUEST_BODY_BYTES {
                        let resp = Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Body::from("Payload Too Large"))?;
                        return Ok((resp, None));
                    }
                }
            }
        }

        let mut collected = Vec::new();
        while let Some(chunk_res) = body.data().await {
            match chunk_res {
                Ok(chunk) => {
                    if collected.len().saturating_add(chunk.len()) > MAX_REQUEST_BODY_BYTES {
                        let resp = Response::builder()
                            .status(StatusCode::PAYLOAD_TOO_LARGE)
                            .body(Body::from("Payload Too Large"))?;
                        return Ok((resp, None));
                    }
                    collected.extend_from_slice(&chunk);
                }
                Err(err) => {
                    error!("Failed reading request body stream: {:?}", err);
                    let resp = Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::from("Bad Request: Failed to read request body"))?;
                    return Ok((resp, None));
                }
            }
        }

        let body_str = String::from_utf8_lossy(&collected).to_string();
        let result = self.run(&parts, body_str).await;

        match result {
            Ok(output) => {
                let mut response = Response::builder();
                response = response.status(output.status);

                if let Some(headers_mut) = response.headers_mut() {
                    for (key, value) in output.headers.iter() {
                        if let (Ok(h_name), Ok(h_val)) = (
                            HeaderName::from_str(key),
                            HeaderValue::from_str(value),
                        ) {
                            headers_mut.insert(h_name, h_val);
                        }
                    }
                }

                let response = response.body(Body::from(output.body()))?;
                Ok((response, None))
            }

            Err(e) => {
                error!("Error: {:?}", e);
                let response = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from("Internal Server Error"))?;
                Ok((response, Some(e)))
            }
        }
    }

    async fn run(&self, parts: &Parts, body: String) -> anyhow::Result<WasmOutput> {
        let mut linker = Linker::new(self.engine());
        bindings::cli::environment::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add environment");
        bindings::cli::exit::add_to_linker(&mut linker, |x| x).expect("Unable to add cli");
        bindings::io::error::add_to_linker(&mut linker, |x| x).expect("Unable to add io error");
        bindings::io::poll::add_to_linker(&mut linker, |x| x).expect("unable to add io poll");
        bindings::io::streams::add_to_linker(&mut linker, |x| x).expect("Unable to add io streams");
        bindings::cli::stdin::add_to_linker(&mut linker, |x| x).expect("Unable to add cli stdin");
        bindings::cli::stdout::add_to_linker(&mut linker, |x| x).expect("Unable to add cli stdout");
        bindings::cli::stderr::add_to_linker(&mut linker, |x| x).expect("Unable to add cli stderr");
        bindings::cli::terminal_input::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add cli terminal input");
        bindings::cli::terminal_output::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add cli terminal output");
        bindings::cli::terminal_stdin::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add cli terminal stdin");
        bindings::cli::terminal_stdout::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add cli terminal stdout");
        bindings::cli::terminal_stderr::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add cli terminal stderr");
        bindings::clocks::monotonic_clock::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add clocks monotonic clock");
        bindings::clocks::wall_clock::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add clocks wallclock");
        bindings::filesystem::types::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add filesystem types");
        bindings::filesystem::preopens::add_to_linker(&mut linker, |x| x)
            .expect("Unable to add filesystem preopens");
        bindings::random::random::add_to_linker(&mut linker, |x| x).expect("Unable to add random");

        let wasi = WasiCtxBuilder::new()
            .inherit_stdout()
            .inherit_stderr()
            .build();

        let table: ResourceTable = ResourceTable::new();

        let mut store = Store::new(
            self.engine(),
            Host {
                table,
                wasi,
                client: None,
            },
        );

        let wasm_input = WasmInput::new(parts, body);
        let request = inbound_http::Request {
            method: match wasm_input.method {
                io::Method::GET => http_types::Method::Get,
                io::Method::POST => http_types::Method::Post,
                io::Method::PUT => http_types::Method::Put,
                io::Method::DELETE => http_types::Method::Delete,
                io::Method::PATCH => http_types::Method::Patch,
                io::Method::HEAD => http_types::Method::Head,
                io::Method::OPTIONS => http_types::Method::Options,
            },
            uri: wasm_input.uri,
            headers: wasm_input.headers,
            params: wasm_input.params,
            body: wasm_input.body,
        };
        wit::Reactor::add_to_linker(&mut linker, |x| x)?;
        let (reactor, _instance) =
            wit::Reactor::instantiate_async(&mut store, self.component(), &linker).await?;
        let guest = reactor.arakoo_edgechains_inbound_http();
        let result: Result<http_types::Response, anyhow::Error> =
            guest.call_handle_request(&mut store, &request).await;
        let mut wasm_output = WasmOutput::new();
        match result {
            Ok(res) => {
                wasm_output.status = res.status;
                wasm_output.status_text = res.status_text;
                let mut headers_map = HashMap::new();
                if let Some(res_headers) = res.headers {
                    for (key, val) in res_headers.iter() {
                        headers_map.insert(key.to_owned(), val.to_owned());
                    }
                }
                wasm_output.headers = headers_map;
                if let Some(body_vec) = res.body {
                    if !body_vec.is_empty() {
                        wasm_output.body = Some(String::from_utf8_lossy(&body_vec).to_string());
                    }
                }
            }
            Err(err) => println!("Error occured : {:?}", err),
        };

        drop(store);
        Ok(wasm_output)
    }
    fn make_service(&self) -> RequestService {
        RequestService::new(self.clone())
    }
}

impl<'addr> Service<&'addr AddrStream> for WorkerCtx {
    type Response = RequestService;
    type Error = Infallible;
    type Future = Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _addr: &'addr AddrStream) -> Self::Future {
        future::ok(self.make_service())
    }
}

impl Service<Request<hyper::Body>> for RequestService {
    type Response = Response<Body>;
    type Error = anyhow::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<hyper::Body>) -> Self::Future {
        let ctx = self.worker_ctx.clone();

        Box::pin(async move { ctx.handle_request(req).await.map(|result| result.0) })
    }
}

fn tracing_subscriber() {
    let verbosity = match env::var("RUST_LOG_VERBOSITY") {
        Ok(s) => s.parse().unwrap_or(0),
        Err(_) => 0,
    };

    if env::var("RUST_LOG").ok().is_none() {
        match verbosity {
            0 => env::set_var("RUST_LOG", "info"),
            1 => env::set_var("RUST_LOG", "debug"),
            _ => env::set_var("RUST_LOG", "trace"),
        }
    }

    let builder = FmtSubscriber::builder()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::from_default_env())
        .with_ansi(true)
        .with_target(false);

    match env::var("RUST_LOG_PRETTY") {
        Ok(s) if s == "true" => builder.pretty().with_level(true).init(),
        _ => builder.with_ansi(false).init(),
    }
    event!(
        Level::DEBUG,
        "RUST_LOG set to '{}'",
        env::var("RUST_LOG").unwrap_or_else(|_| String::from("<Could not get env>"))
    );
}
