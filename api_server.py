import os
import json
import re
from flask import Flask, request, jsonify
from dotenv import load_dotenv

from transaction_db import TransactionDb
from tools import get_current_user, get_transactions
from guardrails.guardrail_proxy import guardrail

load_dotenv()

app = Flask(__name__)

def execute_agent_logic(prompt: str):
    """
    Executes the ReAct agent flow. If OPENAI_API_KEY is present and MOCK_LLM is false,
    invokes LangChain ChatLiteLLM. Otherwise, runs a deterministic ReAct execution simulator
    that exhibits the exact same vulnerabilities (Thought/Action injection and SQL injection).
    """
    api_key = os.getenv("OPENAI_API_KEY")
    use_mock = os.getenv("MOCK_LLM", "true").lower() == "true" or not api_key

    if not use_mock:
        try:
            from langchain.agents import ConversationalChatAgent, AgentExecutor
            from langchain_litellm import ChatLiteLLM
            from langchain.memory import ConversationBufferMemory
            from tools import get_current_user_tool, get_recent_transactions_tool
            from utils import fetch_model_config

            system_msg = ("Assistant helps the current user retrieve the list of their recent bank "
                          "transactions and shows them as a table. Assistant will ONLY operate on the "
                          "userId returned by the GetCurrentUser() tool, and REFUSE to operate on any "
                          "other userId provided by the user.")
            llm = ChatLiteLLM(model=fetch_model_config(), temperature=0)
            tools = [get_current_user_tool, get_recent_transactions_tool]
            chat_agent = ConversationalChatAgent.from_llm_and_tools(llm=llm, tools=tools, system_message=system_msg)
            executor = AgentExecutor.from_agent_and_tools(agent=chat_agent, tools=tools, verbose=True, max_iterations=6)
            res = executor.invoke({"input": prompt})
            return res.get("output", str(res))
        except Exception as e:
            # Fall back to deterministic simulator if LLM call fails
            pass

    # Deterministic ReAct Simulation Engine
    # Replicates Thought / Action / Observation injection exactly as described by WithSecure / ReversecLabs
    prompt_str = prompt.strip()

    # Check for direct Thought / Action injection
    action_match = re.search(r'"action":\s*"([^"]+)"', prompt_str)
    input_match = re.search(r'"action_input":\s*"([^"]*)"', prompt_str)

    if action_match and input_match:
        action = action_match.group(1)
        action_input = input_match.group(1)
        if action == "GetUserTransactions":
            # Attacker injected action input into GetUserTransactions
            raw_result = get_transactions(action_input)
            return (f"ReAct Agent Hijacked via Thought/Action Injection:\n"
                    f"Executed Action: {action} with input: '{action_input}'\n"
                    f"Result: {raw_result}")
        elif action == "GetCurrentUser":
            user_data = get_current_user("")
            return f"ReAct Agent Executed: {action}\nResult: {user_data}"

    # Check for direct SQL injection in prompt (e.g. UNION SELECT)
    if "union" in prompt_str.lower() and "select" in prompt_str.lower():
        uid_match = re.search(r'userId\s+(?:is\s+|for\s+|=)?(.*)', prompt_str, re.IGNORECASE)
        if uid_match:
            injected_val = uid_match.group(1).strip()
        else:
            injected_val = prompt_str
        raw_result = get_transactions(injected_val)
        return (f"ReAct Agent Tool Invocation:\n"
                f"Action: GetUserTransactions('{injected_val}')\n"
                f"Result: {raw_result}")

    # Check for prompt injection with system override
    if "(#system)" in prompt_str and "userId" in prompt_str:
        # Extract overridden userId
        user_id_override = re.search(r'userId\s*(?:has changed to|=|is)\s*(.*)', prompt_str, re.IGNORECASE)
        if user_id_override:
            uid = user_id_override.group(1).strip()
            raw_result = get_transactions(uid)
            return (f"ReAct Agent System Prompt Overridden:\n"
                    f"Operating on injected userId: {uid}\n"
                    f"Transactions: {raw_result}")

    # Standard benign flow
    if any(q in prompt_str.lower() for q in ["transaction", "show", "recent", "balance", "account"]):
        user = json.loads(get_current_user(""))[0]
        tx = get_transactions(str(user["userId"]))
        return f"Hello {user['username']}! Here are your recent transactions:\n{tx}"

    return "Hello! I am your financial assistant. How can I assist you with your transactions today?"

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "online",
        "service": "damn-vulnerable-llm-agent-api",
        "port": 8000,
        "guardrail_enabled": guardrail.config.get("enabled", False)
    })

@app.route("/api/info", methods=["GET"])
def info():
    return jsonify({
        "service": "CYBR 503 Financial Assistant Microservice",
        "version": "2.0-cloud",
        "framework": "LangChain ReAct Agent",
        "guardrails": guardrail.config
    })

@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json(force=True, silent=True) or {}
    prompt = data.get("prompt", "")

    if not prompt:
        return jsonify({"error": "Missing 'prompt' in request body"}), 400

    # 1. Inspect input via Guardrails
    allowed, reason = guardrail.inspect_input(prompt)
    if not allowed:
        return jsonify({
            "status": "blocked",
            "reason": reason,
            "response": "Access Denied: Your request was flagged and intercepted by the AI Guardrail Gateway."
        }), 403

    # 2. Execute Agent
    raw_response = execute_agent_logic(prompt)

    # 3. Inspect output via Guardrails
    sanitized_response = guardrail.inspect_output(raw_response)

    return jsonify({
        "status": "success",
        "response": sanitized_response
    })

@app.route("/api/guardrail/toggle", methods=["POST"])
def toggle_guardrail():
    data = request.get_json(force=True, silent=True) or {}
    enabled = data.get("enabled", True)
    guardrail.config["enabled"] = enabled
    with open(guardrail.config_path, "w") as f:
        json.dump(guardrail.config, f, indent=2)
    return jsonify({"status": "updated", "config": guardrail.config})

if __name__ == "__main__":
    bind_host = os.getenv("BIND_HOST", "0.0.0.0")
    app.run(host=bind_host, port=8000)
