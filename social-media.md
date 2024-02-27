
# Automating Honeypot Attack Processing Using Python and OpenAI


## Introduction
> In this post I will describe the methodology and code I used to automate the processing of honeypot logs using Python and OpenAI. 

> The goal I had was to create a system that can process raw honeypot logs, extract relevant information, and provide an interface for AI to interact with the data to ultimately create full ISC style reports and chat with the AI about a given attack and receive accurate answers backed up by relevant OSINT data. 

The honeypot-ai project can be found here: https://github.com/LucasFaudman/honeypot-ai/tree/main

The system works by providing dynamic access to Attack data and to external OSINT data via OpenAI's new Function/Tool calling feature and the `Assistant` API for context window management.

The topics I will cover in this post are:
 - Converting raw Logs into structured Python objects (`SourceIP`, `Session`, `Malware`, `Attack`)
 - Creating an Interface for AI to interact with `Attack` objects using Function/Tool calling
 - Providing AI Dynamic access to external OSINT data using Function/Tool calling
 - AI Context window management using the Assistant API and threading

## Converting raw Logs into structured Python objects (`SourceIP`, `Session`, `Malware`, `Attack`)
The first step in the overall process is reading the raw logs produced by the services on the honeypot into Python objects. 

My honeypot is running the following software which produce logs:
- Cowrie SSH/Telnet honeypot on ports 22,2233,2222,2223 which produces Cowrie logs in JSON format.
- Dshield Web honeypot on ports 80,8080,443,8443 which produces web logs in JSON format.
- Zeek IDS which produces a variety of logs in Zeek format


The goal of this step is to create `SourceIP`, `Session`, `Malware`, and ultimately `Attack` objects containing them. Each `Attack` contains one or more `SourceIP`s, which contain one or more `Session`s (Cowrie, Web or Both), which each contain `Malware` objects, commands, HTTP requests, etc.
    
### 1. Parsing raw logs into Python objects
The process of parsing logs involves iterating over the log files, reading them with the relevant parser, and standardizing the data into a common format.

To accomplish this I used an abstract class LogParser with .logs() method which returns a generator of standardized log event objects.

For each log type I implemented a subclass of LogParser with a .logs() method that returns a generator of standardized log event objects. For Cowrie and Web logs I used the `json` builtin module to read the logs. For firewall Zeek and logs I wrote a custom parser. 

The standardization process involved making all the events use the same keys for the same data, and converting the data into a common format. For example, the source IP address is always stored in the `src_ip` key, the session identifier is always stored in the `session_id` key, etc.

> Now that we have standardized logs, we can start extracting relevant information into high level `SourceIP`, `Session`, `Malware`, and ultimately `Attack` objects. See this in [logparsers.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/logparser.py)

### 2. Extracting relevant information into sub-objects (`SourceIP`, `Session`, `Malware`)
Processing `SourceIP`, `Session` and `Malware` objects is fairly simple, for each log event check if the `src_ip` of the log event has been seen, if not create it anew SourceIP, then check if the `session_id` exists, if not create a new `Session` and add it to the `SourceIP`. Then depending on the nature of the event, update the `Session` with the relevant information such as commands, HTTP requests, etc. When an event involves an upload or download of a file, create a `Malware` object and add it to the `Session`. 

This process can be seen implemented here in the [`LogProcessor.process_logs_into_source_ips()`](https://github.com/LucasFaudman/honeypot-ai/blob/b44235211ddbdd15031b09909d3763e201a1a674/loganalyzers/logprocessor.py#L162) method. 

> **Recap**: at this point we now have a list of unique `SourceIP`s, each containing a list of unique `Session`s,  containing the relevant information such as commands, HTTP requests, and `Malware` objects for the session.

### 3. Identifying and merging attacks
The next step in the process is to first identify `SourceIPs` with activity that is indicative of an attack, and then merge these `SourceIPs` into `Attack` objects based on the nature of the attack so that `SourceIPs` with similar activity are grouped together into a single `Attack` object.

This is done by iterating over the `SourceIP` objects and checking if the `Session` objects contain any of the following:
- At least one `Malware` object. This is the most clear indicator of an attack since we have a file being uploaded or downloaded.
- At least one successful login attempt in a session.
- At least one command executed in a session. 
- At least one HTTP request in a session that is flagged by regex as a potential attack.

> If a `SourceIP` contains any of the above, it is considered an attacker.

Next the `attack_id`(s) for a `SourceIP` is determined by the nature of the attack and can be any of the following:
- `malware_hash`: SHA256 hash of the `Malware` object after it has been standardized. (More on standardization below)
- `cmdlog_hash`: SHA256 hash of all the commands of a `SourceIP` after they have been standardized.
- `httplog_hash`: SHA256 hash of all the HTTP requests of a `SourceIP` after they have been standardized.

If the `attack_id` is not already in the `Attack` list, a new `Attack` object is created and added to the list, otherwise the `SourceIP` is merged into the existing `Attack` object. This process can be seen here in [`LogProcessor.process_source_ips_into_attacks()`](https://github.com/LucasFaudman/honeypot-ai/blob/b44235211ddbdd15031b09909d3763e201a1a674/loganalyzers/logprocessor.py#L230)


#### Pre-hashing Standardization of Malware, Commands, and HTTP requests using Regexes
To accurately group `SourceIP`s into `Attack` objects, we need to standardize the `Malware`, `Commands`, and `HTTP requests` of a `SourceIP` before hashing them. This is done using regexes to remove data that may change each time an attack is run such as the IP of a C2 server, the path of a file being uploaded, etc.

> Regexes are used to identify values that should be replaced with a common value. 

For example consider an attack that creates a temp_file with a random name. 
The regex `/tmp/([\w\d]+)` would capture the random name of the file so it can be replaced with `X`. Now all attacks that have the same commands will have the same `cmdlog_hash` and can be grouped together regardless of the random file name.

This same process is done before hashing the `Malware` source code and HTTP requests for the same reasons.


#### Merging Attacks based on shared attributes or signatures (more regexes)
The final step in the process is to merge `Attack` objects that are similar based on shared attributes or signatures. This is done by iterating over combinations of `Attack` objects and checking if the any of the following attributes are shared:
- `cmdlog_ips` and `cmdlog_urls`: Unique IPs and URLs found in the `cmdlog` of the `Attack`
- `malware_ips` and `malware_urls`: Unique IPs and URLs found in the `malware` of the `Attack`
- `httplog_ips` and `httplog_urls`: Unique IPs and URLs found in the `httplog` of the `Attack`


> **Recap**: At this point we now have a list of `Attack` objects, each containing a list of `SourceIP`s that engaged in the same activity, each containing a list of `Session`s, containing the relevant information such as commands, HTTP requests, and `Malware` objects for the session. 
> We can now begin to create an interface for AI to interact with the `Attack` objects using Function/Tool calling.

## Create an Interface for AI to interact with Attack objects using Function/Tool calling
The next step in the process is to create an interface for AI to interact with the `Attack` objects. This is done using OpenAI's new Function/Tool calling feature.

### Background on Function/Tool calling
As described in the OpenAI cookbook:
> `tools` is an optional parameter in the Chat Completion API which can be used to provide function specifications. The purpose of this is to enable models to generate function arguments which adhere to the provided specifications.

> Note that the API will not actually execute any function calls. It is up to developers to execute function calls using model outputs.

What this means is a list of functions can be provided to the AI model as a `tool` parameter, and the model will generate function arguments that adhere to the provided specifications. The function call can be executed using the AI model's arguments and then the result can be returned to the AI model for further processing.

The classic example of a `tool` is a function that allows the AI to query current weather data. The AI model can generate arguments for the function such as `city` and `date` and then the function can be executed using the AI model's arguments to return the current weather data for the city and date.

Now when the AI is asked a question about the weather in a city, it can generate the arguments for the weather function and then execute the function to return the current weather data for the city and date before answering the question.
```python
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_current_weather",
            "description": "Get the current weather",
            "parameters": {
                "type": "object",
                "properties": {
                    "location": {
                        "type": "string",
                        "description": "The city and state, e.g. San Francisco, CA",
                    },
                    "format": {
                        "type": "string",
                        "enum": ["celsius", "fahrenheit"],
                        "description": "The temperature unit to use. Infer this from the users location.",
                    },
                },
                "required": ["location", "format"],
            },
        }
    }
]
```
[Read more about Function/Tool calling here](https://cookbook.openai.com/examples/how_to_call_functions_with_chat_models)

### 1. Creating Tools for AI to Interrogate Attack Objects.
Each `Attack` object has a number of attributes that can be queried by the AI model. These include:
- `source_ips`: List of `SourceIP` objects
- `sessions`: List of `Session` objects
- `malware`: List of `Malware` objects
- `commands`: List of commands executed
- `http_requests`: List of HTTP requests made
- `start_time`: Time the attack started
- `end_time`: Time the attack ended
- and more...

The goal here is to create a tool/function definition that allows the AI to query the `Attack` object for its attributes.

To do this I created the tools `get_attack_attrs`, `get_session_attrs`. Each tool takes an argument `attrs` which is a list of attributes to query and returns a dictionary of the attributes and their values. `get_sesion_attrs` and `get_malware_attrs` are similar to `get_attack_attrs` but for `Session` and `Malware` objects and each takes an argument `session_id` and `malware_id` respectively.

Schema of `get_attack_attrs` tool from [tools.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/tools.py):
```python
TOOLS = [
    # Tool function schema for getting attrs of Attack object
    {
        "type": "function",
                "function": {
                    "name": "get_attack_attrs",
                    "description": "Get an attributes of the Attack object",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "attrs": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description":
                                "Attributes of the Attack object to get. Available attrs include: "
                                "src_ips, src_ports, dst_ips, dst_ports, login_pairs, successful_login_pairs, ssh_hasshs, ssh_versions, "
                                "commands, http_requests, "
                                "sessions: Session object ids that can be queried with get_session_attrs, "
                                "malware: Malware object ids that can be queried with get_malware_attrs. "
                                "All attrs return items in chronological order and with duplicates when called without a modifier. "
                                "All attrs can be called with the following modifiers: "
                                "uniq_<attr>: unique items, "
                                "num_<attr>: number of items, "
                                "min_<attr>: minimum value, "
                                "max_<attr>: maximum value, "
                                "most_common_<attr>: most common value, "
                                "most_common<N>_<attr>: N most common values, "
                                "first<attr>: first item (chronologically), "
                                "last_<attr>: last item, "
                                "first<N>_<attr>: first N items, "
                                "last<N>_<attr>: last N items. "
                                "uniq_<attr> can be combined with any other modifier. "
                                "For example, 'first5_uniq_src_ips' returns the first 5 unique source IPs "
                                "and 'num_uniq_http_requests' returns the number of unique HTTP requests. "

                            },
                        },
                        "required": ["attrs"]

                    }
                }
    },
    ...
]
```
`get_session_attrs` and `get_malware_attrs` are similar.

### 2. Using verbose string representations of object to improve AI comprehension
Now the the AI can query data from the `Attack`, `Session`, and `Malware` objects, we need to provide a way for the AI to understand the data it is querying. 

This is done by using verbose human/AI readable representations of objects for the `Attack`, `Session`, and `Malware` objects that can be clearly understood without additional explanation of field names, value types etc. This can be done by overwriting the `__str__` method of the objects to return a verbose string representation of the object.

An example of a verbose representations for a `Session` object:
```python
Session 048ff86571db SSH 158.178.232.193:43052 -> 172.31.5.68:2222 Duration: 0.05s,      
Session a6b312a9d319 SSH 158.178.232.193:44474 -> 172.31.5.68:2222 Login: root:root Commands: 1, Malware: 2, Duration: 0.95s
```
> Now the AI can easily determine which `Session` object it wants to query using the `get_session_attrs` tool. In this case the AI can query the `Session` object with the `session_id` `048ff86571db` for its `commands` and `malware` objects.

Example of the verbose representation for the `Malware` object returned if the AI called `get_session_attrs` with the `malware` attribute as an argument:
```python
Malware c41bcfa6f956acf0d30e9755b24292193f618dc875c071a25fcaeabbe90b688f: Size: 420 bytes Type: text/x-shellscript  Downloaded by: 158.178.232.193 From: http://80.94.92.20/ssh.sh Session f509a0ea1481 Urls:1
```

### 3. Handling AI errors and parameter hallucination
From [Wikipedia](https://en.wikipedia.org/wiki/Hallucination_(artificial_intelligence)):
> In the field of artificial intelligence (AI), a hallucination or artificial hallucination (also called confabulation or delusion) is a response generated by an AI which contains false or misleading information presented as fact. 

In the context of Function/Tool calling, a hallucination is when the AI model generates parameters that are not valid or do not exist, but that seem close to the correct parameters.

#### Simple Parameter Hallucination
For example, consider the `get_attack_attrs` tool the AI model may request the use the argument `ssh_version` which makes sense grammatically, but does not exist as an attribute of the `Attack` object since the actual attribute is `ssh_versions` with an `s`.

Handling this is fairly simple, the objects can be checked for the existence of an attribute with the name of the argument as it is generated by the AI model. If the attribute does not exist, the object is checked for the argument + `s` which does exist and the result is returned to the AI model. For a case where the AI adds an `s` the same process is done but the `s` is removed from the argument before checking the object.

#### Complex Parameter Hallucination
Parameter hallucination can be significantly more complex than simple pluralization errors. For example consider the `get_attack_attrs` tool the AI model may request the use the argument `first_src_ip` which makes sense grammatically, and can logically be inferred to mean the first source IP in the `Attack` object. But the actual attribute is `src_ips` which is a list of source IPs and not a single source IP.

The obvious way to handle this is to simply return an error to the AI model, but this is not ideal since it requires additional requests and tokens before the AI can get the data it needs.

Instead we can leverage this to our advantage using a custom base object called a `SmartAttrObject` that can handle complex parameter hallucination. The `SmartAttrObject` can be used as a base class for the `Attack`, `Session`, and `Malware` objects to allow the AI model to query the objects for complex attributes that do not exist, but can be calculated from the existing attributes.

For example consider the `first_src_ip` attribute. The `SmartAttrObject` can be used to calculate the first source IP in the `Attack` object by simply returning the first item in the `src_ips` attribute. The same process can be done for other complex attributes such as `most_common_http_request`, `uniq_malware`, `num_commands`, etc.

This can be seen implemented in the `SmartAttrObject` class in [baseobjects.py](https://github.com/LucasFaudman/honeypot-ai/blob/b44235211ddbdd15031b09909d3763e201a1a674/analyzerbase/baseobjects.py#L15)


> **Recap**: Now our tools can be used to query the `Attack`, `Session`, and `Malware` objects for their attributes and the AI model can easily understand the data it is querying. Errors and parameter hallucination are handled by the `SmartAttrObject` base class.

## Provide AI Dynamic access to external OSINT data 
The next step for our AI to be able to understand the `Attack` objects is to provide it with dynamic access to external OSINT data so that it can investigate the attributes of the `Attack` object such as `src_ips`, `commands`, `malware`, etc.

> This is done by collecting OSINT data from a variety of sources and providing the AI model with a tool that allows it to query the OSINT data for relevant information using values from the `Attack` object as arguments.

### 1. Backend collection of OSINT data
Collection of OSINT data is done by using a variety of APIs and web scraping to collect data from a variety of sources such as:
- Cybergordon
- ThreatFox
- ISC
- Whois
- Shodan
- UrlHaus
- MalwareBazaar
- ExploitDB
- and more...

The process of collection for sources that have APIs is straightforward, simply make a request to the API with the relevant arguments and parse the response into a standardized format. 

For sources that do not have an API or that require an API key, web scraping is used to collect the data using a tool I developed for a previous project called [`SoupScraper`](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/soupscraper.py) which combines `BeautifulSoup` and `selenium` to scrape data from webpages.

This can be seen here in [`IPAnalyzer`](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/ipanalyzer.py) and [`MalwareAnalyzer`](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/malwareanalyzer.py) classes.

### 2. Simple interface for AI to query OSINT data
Now that we can collect OSINT data the AI needs a way to access it and to understand which source to query for which data. This is done by creating a tool that allows the AI to query the OSINT data for relevant information using values from the `Attack` object as arguments such as `src_ips`.

Here is an example of the tool schema for querying OSINT data for an IP address:
```python
TOOLS = [
    # Tool function schema for querying IP data from OSINT sources: CyberGordon, Shodan, and ISC
    {
        "type": "function",
        "function": {
                "name": "query_ip_data",
                "description": "Query IP address data from OSINT sources.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "ips": {"type": "array",
                                "description": "A list of IP address(es) to query data for.",
                                "items": {"type": "string"}},
                        "sources": {"type": "array",
                                    "description":
                                        "The source(s) to get data from: "
                                        "cybergordon: IP data summaries from a variety of other OSINT sources, "
                                        "shodan: port & geolocation data, "
                                        "isc: geolocation & attack report counts from other honeypots",
                                    "items": {
                                        "type": "string",
                                        "enum": ["cybergordon", "shodan", "isc"]
                                    }},
                    },
                    "required": ["ip", "sources"]
                }
        }
    }
]
```

The reason why one tool is used for multiple sources is because the AI can only handle a limited number of tools at a time and it is more efficient to query multiple sources at once than to have a tool for each source.

However some sources whose function is significantly different from the others such as ExploitDB and MalwareBazaar have their own tools.

The ExploitDB tools for example allow the AI to query the ExploitDB for exploits that match the `Attack` object's `commands` and `http_requests` using the `search_exploitdb` tool.

Then the AI can use `get_exploitdb_exploit` to get the details and code for a specific exploit to see if it is consistent with the `Attack`.

Here is an example of the tool schema for querying ExploitDB for exploits:
```python
TOOLS = [
    # Tool function schema for querying ExploitDB for exploit search results
    {
        "type": "function",
        "function": {
                "name": "search_exploitdb",
                "description": "Search ExploitDB for exploit code containing the specified text",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "search_text": {
                            "type": "string",
                            "description": "The text to search for in the ExploitDB database. "
                            "The text should be code or a string literal that would be found in an exploit "
                            "and must be as specific as possible to avoid false positives. "
                            "(eg minio/admin/v3/update?updateURL=, pearcmd.php, )"
                        },
                    },
                    "required": ["search_text"]
                }
        }
    },


    # Tool function schema for querying ExploitDB for exploit details
    {
        "type": "function",
        "function": {
                "name": "get_exploitdb_exploit",
                "description": "Get details about an exploit from ExploitDB",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "exploit_id": {
                            "type": "string",
                            "description": "The id of the exploit to get details for. "
                            "exploit_ids can be found in the output of search_exploitdb function calls."
                        },
                    },
                    "required": ["exploit_id"]
                }
        }
    },

]
```

> **Recap**: Now the AI model can query the OSINT data for relevant information using values from the `Attack` object as arguments.

### 3. Reducing token usage
The last consideration when providing data from external sources to an AI model is to reduce the number of tokens used to query the data. This is done by providing the AI model with a reduced version of the data from the OSINT sources instead of the raw data.

> To understand why this matters it is essential to first understand tokens in the context of AI.

From [OpenAI's documentation](https://help.openai.com/en/articles/4936856-what-are-tokens-and-how-to-count-them):

> Tokens can be thought of as pieces of words. Before the API processes the prompts, the input is broken down into tokens. These tokens are not cut up exactly where the words start or end - tokens can include trailing spaces and even sub-words. Here are some helpful rules of thumb for understanding tokens in terms of lengths:
> - 1 token ~= 4 chars in English
> - 1 token ~= ¾ words
> - 100 tokens ~= 75 words
> - Or 
> - 1-2 sentence ~= 30 tokens
> - 1 paragraph ~= 100 tokens
> - 1,500 words ~= 2048 tokens
> 
> To get additional context on how tokens stack up, consider this:
> Wayne Gretzky’s quote "You miss 100% of the shots you don't take" contains 11 tokens.

So to reduce the number of tokens used to query the OSINT data, all empty values, useless values such as `None`, and long values such as the full WHOIS text are removed from the data before it is returned to the AI model, since each character increase the number tokens.

## AI Context window management using the Assistant API
Now that we have a way for the AI model to query the `Attack` objects and the OSINT data, we need to provide a way for the AI model to manage the context window of the data it is querying.

> A context window is the data (tokens) that the AI model has access to at any given time. This is important because the AI model can only handle a limited number of tokens at a time.

The context window is managed using the Assistant API which allows the AI model to manage the context window of the data it is querying by providing a way to store and retrieve the data from the context window.

From [OpenAI's documentation](https://help.openai.com/en/articles/4936856-what-are-tokens-and-how-to-count-them):
> The Assistants API automatically manages the context window such that you never exceed the model's context length. Once the size of the Messages in a Thread exceeds the context window of the model, the Thread will attempt to include as many messages as possible that fit in the context window and drop the oldest messages. Note that this truncation strategy will evolve over time to become more sophisticated.
>
> Currently, the Assistant will include the maximum number of messages that fit in the context length. We plan to explore the ability for you to control the input / output token count beyond the model you select, as well as the ability to automatically generate summaries of the previous messages and pass that as context. If your use case requires a more advanced level of control, you can manually generate summaries and control context with the Chat Completion API.

What this means is that we need to make sure the right data is in the context window at the right time so that the AI model can accurately answer questions about the `Attack` objects and the OSINT data.

### 1. Prompt order
The order of the prompts is extremely important because it is necessary to ask questions in an order that allows the AI model to build a complete understanding of the `Attack` object and the OSINT data.

For example consider the following prompts:
1. "Explain how the malware functions in the context of the attack."
2. "What are the indicators of compromise (IOCs) for this attack?"

In this example it is necessary to ask the first question before the second question because the first question allows the AI model to build a complete understanding of the `Attack` object's malware and the OSINT data before the second question is asked.

Asking the second question before the first question would result in the AI model not having enough information to accurately answer the question.

### 2. Context window size
The context window size is dependent on the AI model being used and varies signifcantly between models. For example the latest models like `gpt-4-0125-preview` can handle 128,000 tokens of context, while older models like `gpt-3.5-turbo` can only handle 4096 tokens of context.

This means that the amount of data that can be accurately queried at a time is dependent on the AI model being used and its context window size.

### 3. Threading
When using the `Assistants` API to manage the context window, it is necessary to use threading to manage the context window of the data being queried by the AI model for each specific `Attack` object.

From [OpenAI's documentation](https://platform.openai.com/docs/assistants/how-it-works/managing-threads-and-messages):
> Threads and Messages represent a conversation session between an Assistant and a user. There is no limit to the number of Messages you can store in a Thread. Once the size of the Messages exceeds the context window of the model, the Thread will attempt to include as many messages as possible that fit in the context window and drop the oldest messages.

What this means is that each Attack should be analyzed on a separate thread to avoid the context window being filled with data from other `Attack` objects.

Additionally threading allows for questions to be asked interactively or at a later time without the AI model losing context of the `Attack` object and the OSINT data.

### 4. Interactive chat purposes    
Interactive chat is another feature of `honeypot-ai` which is very useful for adding additional context to the AI model's understanding of the `Attack` object and the OSINT data.

For example if you have a hunch that a given exploit was used in an attack you can ask the AI model to search for the exploit in the `Attack` object's `commands` and `http_requests` using the `search_exploitdb` tool and then ask the AI model to explain how the exploit works in the context of the `Attack` object. 

An example of this can be seen here: [Why do you think its exploit 32512 not 11442?](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/FreePBX%20Exploit%20Usage%20with%20Cryptocurrency%20Mining%20Payloads%20by%20Attacker%20from%20Amsterdam/run-steps.md#answer-15)

## Putting it all together
With a complete framework for AI to interact with `Attack` objects and OSINT data, the AI model can now be used to generate full ISC style reports and chat with the AI about a given attack and receive accurate answers backed up by relevant OSINT data.

Reports are generated via the `MarkdownWriter` subclasses [`AttackMarkdownWriter`](https://github.com/LucasFaudman/honeypot-ai/blob/b44235211ddbdd15031b09909d3763e201a1a674/markdownwriters/attackmarkdownwriter.py#L6) [`IPMarkdownWriter`](https://github.com/LucasFaudman/honeypot-ai/blob/b44235211ddbdd15031b09909d3763e201a1a674/markdownwriters/ipmarkdownwriter.py#L6) and which programmatically generate markdown from the values of the `Attack` object, the OSINT data and AI model's answers.

An example of a full ISC style report can be seen here: [Log4Shell Exploitation Attempt from Poland-based IPs Seeking Unauthorized Access for Cryptojacking and Potential Botnet Propagation](https://github.com/LucasFaudman/honeypot-ai/tree/main/example-reports/Log4Shell%20Exploitation%20Attempt%20from%20Poland-based%20IPs%20Seeking%20Unauthorized%20Access%20for%20Cryptojacking%20and%20Potential%20Botnet%20Propagation)

