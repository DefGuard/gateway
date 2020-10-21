use hello::say_server::{Say, SayServer};
use hello::{SayRequest, SayResponse};
use tonic::{transport::Server, Request, Response, Status};
mod hello;

// defining a struct for our service
#[derive(Default)]
pub struct MySay {}

// implementing rpc for service defined in .proto
#[tonic::async_trait]
impl Say for MySay {
    // our rpc impelemented as function
    async fn send(&self, request: Request<SayRequest>) -> Result<Response<SayResponse>, Status> {
        // returning a response as SayResponse message as defined in .proto
        let message = format!("hello {}", request.get_ref().name);
        println!("Responding with message: {}", message);
        Ok(Response::new(SayResponse {
            // reading data from request which is awrapper around our SayRequest message defined in .proto
            message: message, 
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // defining address for our service
    let addr = "[::1]:50051".parse().unwrap();
    // creating a service
    let say = MySay::default();
    println!("Server listening on {}", addr);
    // adding our service to our server.
    Server::builder()
        .add_service(SayServer::new(say))
        .serve(addr)
        .await?;
    Ok(())
}
