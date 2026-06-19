# Configuration

## Environment Variables
- OPENAI_BASE_URL: base URL of any OpenAI-compatible LLM endpoint
- OPENAI_API_KEY: API key for the LLM service
- MODEL: model name to use (e.g., gpt-4o)

Point at any OpenAI-compatible LLM by setting OPENAI_BASE_URL and OPENAI_API_KEY.

## Framework Selection
Select compliance framework via configuration: GDPR, PCI, HIPAA, or SOC2.

## Policy / Evidence Storage Paths
Configure local or vault paths for policy documents and collected evidence.

## Docker-Compose / .env Workflow
Create a .env file with the variables above, then run:
docker compose up

All services read configuration exclusively from the environment.