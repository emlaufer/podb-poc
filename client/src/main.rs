use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lib::api::{AcceptInviteRequest, AcceptInviteResponse};
use lib::membership::{MembershipProver, MembershipVerifier};
use pod2::backends::plonky2::signer::Signer;
use pod2::frontend::MainPod;
use pod2::middleware::{PublicKey, SecretKey, Signer as SignerTrait};
use reqwest::Client;
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "podb-client")]
#[command(about = "A CLI client for the PODB membership system with proof generation")]
#[command(version = "0.1.0")]
struct Cli {
    #[arg(long, default_value = "http://localhost:3000")]
    server_url: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new keypair and save to files
    GenerateKeypair {
        #[arg(long, default_value = "keypair")]
        name: String,
    },

    /// Generate an invite pod for a member
    GenerateInvite {
        /// Path to admin private key file
        #[arg(long)]
        admin_key: PathBuf,

        /// Path to the member's public key file to invite
        #[arg(long)]
        invite_member: PathBuf,

        /// Output file for the invite pod
        #[arg(long, default_value = "invite.pod")]
        output: PathBuf,
    },

    /// Accept an invite and submit to server
    AcceptInvite {
        /// Path to the invite pod file
        #[arg(long)]
        invite_pod: PathBuf,

        /// Path to the invitee's private key
        #[arg(long)]
        invitee_key: PathBuf,

        /// Output file for the accept pod
        #[arg(long, default_value = "accept.pod")]
        output: PathBuf,
    },

    /// Submit accept invite pod to server
    SubmitAccept {
        /// Path to accept invite pod file
        #[arg(long)]
        accept_pod: PathBuf,

        /// Path to the member's public key file
        #[arg(long)]
        member_public_key: PathBuf,
    },

    /// Check server status
    Status,
}

struct PodobClient {
    client: Client,
    base_url: String,
    prover: MembershipProver,
    verifier: MembershipVerifier,
}

impl PodobClient {
    fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
            prover: MembershipProver::new(),
            verifier: MembershipVerifier::new(),
        }
    }

    async fn submit_accept_invite(
        &self,
        accept_pod: MainPod,
        member_public_key: PublicKey,
    ) -> Result<AcceptInviteResponse> {
        let url = format!("{}/membership/accept-invite", self.base_url);
        let request = AcceptInviteRequest {
            accept_invite_pod: accept_pod,
            new_member_public_key: member_public_key,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to send request to server")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Server returned error: {}", error_text);
        }

        let result: AcceptInviteResponse = response
            .json()
            .await
            .context("Failed to parse server response")?;

        // Verify the state transition proof returned by the server
        if result.success {
            println!("Verifying state transition proof...");

            // Verify the update proof with the commitments provided by server
            match self.verifier.verify_update_state(
                &result.update_proof,
                &result.old_state_commitment,
                &result.new_state_commitment,
            ) {
                Ok(true) => println!("✓ Server's state transition proof verified successfully!"),
                Ok(false) => {
                    println!("⚠ Warning: Server's state transition proof verification failed!");
                }
                Err(e) => {
                    println!(
                        "⚠ Warning: Failed to verify server's state transition proof: {:?}",
                        e
                    );
                }
            }

            println!("✓ State transition verification complete");
        }

        Ok(result)
    }

    async fn check_status(&self) -> Result<()> {
        let url = format!("{}/", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to server")?;

        if response.status().is_success() {
            let result: serde_json::Value = response
                .json()
                .await
                .context("Failed to parse server response")?;

            if let Some(message) = result.get("message") {
                println!("Server status: {}", message.as_str().unwrap_or("OK"));
            } else {
                println!("Server is running");
            }
        } else {
            anyhow::bail!("Server is not responding (status: {})", response.status());
        }

        Ok(())
    }

    async fn get_is_admin_proof(&self, public_key: PublicKey) -> Result<MainPod> {
        let url = format!("{}/membership/prove-is-admin", self.base_url);
        let request = lib::api::IsAdminProofRequest { public_key };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Server returned error: {}", error_text);
        }

        let result: lib::api::IsAdminProofResponse = response
            .json()
            .await
            .context("Failed to parse server response")?;

        if !result.success {
            anyhow::bail!("Server failed to generate is_admin proof");
        }

        Ok(result.is_admin_proof)
    }

    async fn get_state_commitment(&self) -> Result<pod2::middleware::Hash> {
        let url = format!("{}/membership/state-commitment", self.base_url);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context("Failed to connect to server")?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            anyhow::bail!("Server returned error: {}", error_text);
        }

        let result: lib::api::StateCommitmentResponse = response
            .json()
            .await
            .context("Failed to parse server response")?;

        println!(
            "Fetched state commitment with {} members",
            result.member_count
        );

        Ok(result.state_commitment)
    }

    fn generate_keypair(&self, name: &str) -> Result<()> {
        let secret_key = SecretKey::new_rand();
        let public_key = secret_key.public_key();

        // Save private key as JSON
        let private_key_file = format!("{}.private", name);
        let private_key_json =
            serde_json::to_string_pretty(&secret_key).context("Failed to serialize private key")?;
        fs::write(&private_key_file, private_key_json)
            .context("Failed to write private key file")?;

        // Save public key as JSON
        let public_key_file = format!("{}.public", name);
        let public_key_json =
            serde_json::to_string_pretty(&public_key).context("Failed to serialize public key")?;
        fs::write(&public_key_file, public_key_json).context("Failed to write public key file")?;

        println!("Generated keypair:");
        println!("  Private key: {}", private_key_file);
        println!("  Public key:  {}", public_key_file);
        println!("  Public key value: {:?}", public_key);

        Ok(())
    }

    async fn generate_invite(
        &self,
        admin_key_path: &PathBuf,
        invite_member_path: &PathBuf,
        output_path: &PathBuf,
    ) -> Result<()> {
        // Load admin private key from JSON
        let admin_key_json =
            fs::read_to_string(admin_key_path).context("Failed to read admin private key file")?;
        let admin_secret: SecretKey = serde_json::from_str(&admin_key_json)
            .context("Failed to deserialize admin private key from JSON")?;
        let admin_signer = Signer(admin_secret);

        // Load invite member public key from JSON
        let invite_member_json = fs::read_to_string(invite_member_path)
            .context("Failed to read invite member public key file")?;
        let invite_member_pk: PublicKey = serde_json::from_str(&invite_member_json)
            .context("Failed to deserialize invite member public key from JSON")?;

        // Get is_admin proof from server
        println!("Getting is_admin proof from server...");
        let is_admin_proof = self
            .get_is_admin_proof(admin_signer.public_key())
            .await
            .context("Failed to get is_admin proof from server")?;

        // Get state commitment from server
        println!("Getting state commitment from server...");
        let state_commitment = self
            .get_state_commitment()
            .await
            .context("Failed to get state commitment from server")?;

        // Generate invite pod using state commitment and is_admin proof
        println!("Generating invite pod...");
        let invite_pod = self
            .prover
            .prove_invite(
                state_commitment,
                invite_member_pk,
                &admin_signer,
                &is_admin_proof,
            )
            .context("Failed to generate invite pod")?;

        // Serialize pod to file
        let pod_json =
            serde_json::to_string_pretty(&invite_pod).context("Failed to serialize invite pod")?;
        fs::write(output_path, pod_json).context("Failed to write invite pod file")?;

        println!(
            "Invite pod generated and saved to: {}",
            output_path.display()
        );
        Ok(())
    }

    async fn accept_invite(
        &self,
        invite_pod_path: &PathBuf,
        invitee_key_path: &PathBuf,
        output_path: &PathBuf,
    ) -> Result<()> {
        // Load invite pod
        let pod_json =
            fs::read_to_string(invite_pod_path).context("Failed to read invite pod file")?;
        let invite_pod: MainPod =
            serde_json::from_str(&pod_json).context("Failed to deserialize invite pod")?;

        // Load invitee private key from JSON
        let invitee_key_json = fs::read_to_string(invitee_key_path)
            .context("Failed to read invitee private key file")?;
        let invitee_secret: SecretKey = serde_json::from_str(&invitee_key_json)
            .context("Failed to deserialize invitee private key from JSON")?;
        let invitee_signer = Signer(invitee_secret);

        // Get state commitment from server
        println!("Getting state commitment from server...");
        let state_commitment = self
            .get_state_commitment()
            .await
            .context("Failed to get state commitment from server")?;

        // Generate accept invite pod using state commitment
        println!("Generating accept invite pod...");
        let accept_pod = self
            .prover
            .prove_accept_invite(state_commitment, &invitee_signer, &invite_pod)
            .context("Failed to generate accept invite pod")?;

        // Serialize pod to file
        let pod_json =
            serde_json::to_string_pretty(&accept_pod).context("Failed to serialize accept pod")?;
        fs::write(output_path, pod_json).context("Failed to write accept pod file")?;

        println!(
            "Accept invite pod generated and saved to: {}",
            output_path.display()
        );
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = PodobClient::new(cli.server_url);

    match cli.command {
        Commands::GenerateKeypair { name } => {
            client.generate_keypair(&name)?;
        }

        Commands::GenerateInvite {
            admin_key,
            invite_member,
            output,
        } => {
            client
                .generate_invite(&admin_key, &invite_member, &output)
                .await?;
        }

        Commands::AcceptInvite {
            invite_pod,
            invitee_key,
            output,
        } => {
            client
                .accept_invite(&invite_pod, &invitee_key, &output)
                .await?;
        }

        Commands::SubmitAccept {
            accept_pod,
            member_public_key,
        } => {
            // Load accept pod
            let pod_json =
                fs::read_to_string(&accept_pod).context("Failed to read accept pod file")?;
            let accept_pod: MainPod =
                serde_json::from_str(&pod_json).context("Failed to deserialize accept pod")?;

            // Load member public key from JSON file
            let member_pk_json = fs::read_to_string(&member_public_key)
                .context("Failed to read member public key file")?;
            let member_pk: PublicKey = serde_json::from_str(&member_pk_json)
                .context("Failed to deserialize member public key from JSON")?;

            // Submit to server
            println!("Submitting accept invite pod to server...");
            let response = client.submit_accept_invite(accept_pod, member_pk).await?;

            if response.success {
                println!("✓ Member successfully added to membership!");
                println!("  New member count: {}", response.new_member_count);
            } else {
                println!("✗ Failed to add member");
            }
        }

        Commands::Status => {
            client.check_status().await?;
        }
    }

    Ok(())
}
