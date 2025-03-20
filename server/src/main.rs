use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use serde::Deserialize;
use std::{fs::File, io::Read};

// Structure for deserializing the JSON file containing the circuit bytecode.
#[derive(Deserialize)]
struct CircuitConfig {
    bytecode: String,
}

// Helper function to load the bytecode from a JSON file.
fn load_bytecode_from_file(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: CircuitConfig = serde_json::from_str(&contents)?;
    Ok(config.bytecode)
}

// Incoming JSON payload for registration.
// `proof` is the Noir proof and `voprf_input` is a hex-encoded blinded element.
#[derive(Deserialize)]
struct RegistrationRequest {
    proof: String,
    voprf_input: String,
}

#[post("/registration")]
async fn registration_handler(req: web::Json<RegistrationRequest>) -> impl Responder {
    // Verify the Noir proof using our updated logic.
    if !verify_noir_proof(&req.proof) {
        return HttpResponse::BadRequest().body("Invalid proof");
    }

    // Call the VOPRF API using the voprf crate.
    match call_voprf_api(&req.voprf_input) {
        Ok(result) => HttpResponse::Ok().body(format!("VOPRF evaluation result: {}", result)),
        Err(e) => {
            HttpResponse::InternalServerError().body(format!("Error calling VOPRF API: {}", e))
        }
    }
}

/// Verifies a Noir proof using the noir_rs crate.
///
/// It loads the circuit bytecode from a JSON file, sets up the SRS,
/// retrieves the verification key (passing `None` as the second argument),
/// and then verifies the proof using `verify_ultra_honk`.
fn verify_noir_proof(proof_str: &str) -> bool {
    use noir_rs::barretenberg::{
        srs::{setup_srs, setup_srs_from_bytecode},
        utils::get_honk_verification_key,
        verify::verify_ultra_honk,
    };

    // Load the bytecode from an external JSON file.
    // Adjust the path to match your project structure.
    let bytecode = match load_bytecode_from_file("../core/target/identity.json") {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error loading bytecode from file: {:?}", e);
            return false;
        }
    };

    // Setup the SRS using the bytecode.
    if let Err(e) = setup_srs_from_bytecode(&bytecode, None, false) {
        eprintln!("Error setting up SRS from bytecode: {:?}", e);
        return false;
    }

    // Retrieve the verification key.
    // Note the addition of the second argument (None) to match the expected signature.
    let vk = match get_honk_verification_key(&bytecode, None) {
        Ok(vk) => vk,
        Err(e) => {
            eprintln!("Error getting verification key: {:?}", e);
            return false;
        }
    };

    // Verify the proof.
    match verify_ultra_honk(proof_str.to_string(), vk) {
        Ok(verdict) => {
            println!("Proof verification verdict: {}", verdict);
            verdict
        }
        Err(e) => {
            eprintln!("Error during proof verification: {:?}", e);
            false
        }
    }
}

/// Calls the VOPRF API using the voprf crate.
///
/// It decodes the hex-encoded blinded input, sets up a VOPRF server instance, and evaluates the blinded element.
/// The evaluation result is returned as a hex-encoded string.
fn call_voprf_api(blinded_hex: &str) -> Result<String, String> {
    // Decode the hex-encoded blinded input into bytes.
    let blinded_bytes =
        hex::decode(blinded_hex).map_err(|e| format!("Invalid hex in blinded input: {:?}", e))?;

    use rand::rngs::OsRng;
    use voprf::oprf::{ServerSetup, VoprfServer};

    let mut rng = OsRng;
    let server_setup =
        ServerSetup::new(&mut rng).map_err(|e| format!("Server setup error: {:?}", e))?;
    let server = VoprfServer::new(server_setup);

    // Evaluate the blinded element.
    let evaluation = server
        .evaluate(&blinded_bytes)
        .map_err(|e| format!("Evaluation error: {:?}", e))?;

    // Convert the evaluation result to a hex string.
    Ok(hex::encode(evaluation))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Start the Actix Web server on localhost:8080.
    HttpServer::new(|| App::new().service(registration_handler))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
