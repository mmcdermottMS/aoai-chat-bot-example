import os
import logging
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from openai import AzureOpenAI

# Azure OpenAI setup
deployment_id = os.environ["AZURE_OPENAI_DEPLOYMENT_ID"]
aoaiClient = AzureOpenAI(
    api_version = "2024-02-15-preview",
    azure_endpoint = os.environ["AZURE_OPENAI_API_URI"],
    azure_deployment = deployment_id
)

kvSecretClient = SecretClient(vault_url=os.environ["KEY_VAULT_URI"], credential=DefaultAzureCredential())

app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@app.route(route="chat")
async def chat(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logging.info('Python HTTP trigger function processed a request.')
        
        # Azure AI Search setup
        search_endpoint = os.environ["AZURE_AI_SEARCH_URI"]; # Add your Azure AI Search endpoint here
        search_index_name = os.environ["AZURE_AI_SEARCH_INDEX_NAME"]; # Add your Azure AI Search index name here

        question = req.params.get('question')
        if not question:
            try:
                req_body = req.get_json()
            except ValueError:
                pass
            else:
                question = req_body.get('question')
        
        messages = [
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
        
        completion = aoaiClient.chat.completions.create(**model_args)
        
        if(len(completion.choices) > 0):
            answer = completion.choices[0].message.content
        else:
            answer = "no answer"

        if question:
            #try:
                return func.HttpResponse(
                    f"Hello, {question}. This HTTP triggered function executed successfully. Answer: {answer}", 
                    status_code=200
                )
            #except Exception as e:
            #    return func.HttpResponse(
            #        f"Exception: {e}", 
            #        status_code=200
            #    )
                
        else:
            return func.HttpResponse(
                "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
                status_code=200
            )
        
    except Exception as e:
        return func.HttpResponse(f"Exception: {e}", status_code=200)
        
    
async def getKeyVaultSecret(secretName: str) -> str:
    return kvSecretClient.get_secret(secretName).value