import os
import logging
import azure.functions as func
from azure.identity.aio import DefaultAzureCredential
from azure.keyvault.secrets.aio import SecretClient
from openai import AsyncAzureOpenAI # Import the Async client for async/await support

# Azure Application Insights setup
from azure.monitor.opentelemetry import configure_azure_monitor
from opentelemetry import trace
from opentelemetry.propagate import extract

configure_azure_monitor() # Be sure that APPINSIGHTS_INSTRUMENTATIONKEY is configured in environment variables or this call will fail

# Azure OpenAI setup.  Be sure that AZURE_OPENAI_API_KEY is configured in environment variables or this call will fail
# //TODO: Migrate from API Key to Managed Identity
deployment_id = os.environ["AZURE_OPENAI_DEPLOYMENT_ID"]
aoaiClient = AsyncAzureOpenAI(
    api_version = "2024-02-15-preview",
    azure_endpoint = os.environ["AZURE_OPENAI_API_URI"],
    azure_deployment = deployment_id
)

# Create a Kev Vault Secrets client
kvSecretClient = SecretClient(vault_url=os.environ["KEY_VAULT_URI"], credential=DefaultAzureCredential())

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

#TODO: Implement function level API key for callers to use
@app.route(route="chat")
async def chat(req: func.HttpRequest, context) -> func.HttpResponse:
    
    # Extract the trace context from the incoming request
    carrier = {
      "traceparent": context.trace_context.Traceparent,
      "tracestate": context.trace_context.Tracestate,
    }
    
    # Create a new Open Telemetry span with the incoming trace context
    tracer = trace.get_tracer(__name__)
    with tracer.start_as_current_span("chat", context = extract(carrier)): # span name matches the function name
        try:
            logging.info('Chat API called')
            
            # Azure AI Search setup
            search_endpoint = os.environ["AZURE_AI_SEARCH_URI"]
            search_index_name = os.environ["AZURE_AI_SEARCH_INDEX_NAME"]

            question = req.params.get('question')
            if not question:
                try:
                    req_body = req.get_json()
                except ValueError:
                    pass
                else:
                    question = req_body.get('question')
                    
            #TODO: Layer in message history here
            if question:            
                messages = [
                        {
                            "role": "system",
                            "content": "You are an AI assistant that helps people find information."
                        },
                        {
                            "role": "user",
                            "content": question
                        }
                    ]
                
                azure_search_api_key = await getKeyVaultSecret("azure-search-api-key")
                
                azure_search_data_source = {
                    "type": "azure_search",
                    "parameters": {
                        "endpoint": search_endpoint,
                        "authentication": {
                            "type": "api_key",
                            "key": azure_search_api_key
                        },
                        "index_name": search_index_name,
                        "fields_mapping": {},
                        "in_scope": True,
                        "top_n_documents": 10, #TODO: configurize this
                        "query_type": "simple",
                        "role_information": "You are an AI assistant that helps people find information.",
                        "filter": None
                    }
                }
                
                model_args = {
                    "messages": messages,
                    "model": deployment_id, #this is the name of the deployment from Azure AI Studio
                    "extra_body": {
                        "data_sources": [
                            azure_search_data_source
                        ]
                    }
                }
                
                completion = await aoaiClient.chat.completions.create(**model_args)
                
                if(len(completion.choices) > 0):
                    answer = completion.choices[0].message.content
                else:
                    answer = "no answer"

                return func.HttpResponse(
                    f"Question Submitted: {question}. Answer: {answer}", 
                    status_code=200
                )
        
            else:
                return func.HttpResponse(
                    "Please specify a question prompt in the 'question' query string parameter or in the body of the request.",
                    status_code=200
                )
            
        except Exception as e:
            return func.HttpResponse(f"Exception: {e}", status_code=200)
        
    
async def getKeyVaultSecret(secretName: str) -> str:
    secret = await kvSecretClient.get_secret(secretName)
    return secret.value