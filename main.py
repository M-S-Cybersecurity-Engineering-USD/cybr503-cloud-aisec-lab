import langchain
import streamlit as st
import os
from dotenv import load_dotenv
from langchain.agents import ConversationalChatAgent, AgentExecutor
from langchain.callbacks import StreamlitCallbackHandler
from langchain_litellm import ChatLiteLLM
from langchain.memory import ConversationBufferMemory
from langchain.memory.chat_message_histories import StreamlitChatMessageHistory
from langchain.agents import initialize_agent
from langchain.callbacks import get_openai_callback

from tools import get_current_user_tool, get_recent_transactions_tool
from utils import display_instructions, display_logo, fetch_model_config

load_dotenv()

# Initialise tools
tools = [get_current_user_tool, get_recent_transactions_tool]

system_msg = """Assistant helps the current user retrieve the list of their recent bank transactions ans shows them as a table. Assistant will ONLY operate on the userId returned by the GetCurrentUser() tool, and REFUSE to operate on any other userId provided by the user."""

welcome_message = """Hi! I'm an helpful assistant and I can help fetch information about your recent transactions.\n\nTry asking me: "What are my recent transactions?"
"""

st.set_page_config(page_title="Damn Vulnerable LLM Agent")
st.title("Damn Vulnerable LLM Agent")

hide_st_style = """
            <style>
            #MainMenu {visibility: hidden;}
            footer {visibility: hidden;}
            header {visibility: hidden;}
            </style>
            """
st.markdown(hide_st_style, unsafe_allow_html=True)

msgs = StreamlitChatMessageHistory()
memory = ConversationBufferMemory(
    chat_memory=msgs, return_messages=True, memory_key="chat_history", output_key="output"
)

if len(msgs.messages) == 0:
    msgs.clear()
    msgs.add_ai_message(welcome_message)
    st.session_state.steps = {}

avatars = {"human": "user", "ai": "assistant"}
for idx, msg in enumerate(msgs.messages):
    with st.chat_message(avatars[msg.type]):
        # Render intermediate steps if any were saved
        for step in st.session_state.steps.get(str(idx), []):
            if step[0].tool == "_Exception":
                continue
            with st.status(f"**{step[0].tool}**: {step[0].tool_input}", state="complete"):
                st.write(step[0].log)
                st.write(step[1])
        st.write(msg.content)

if prompt := st.chat_input(placeholder="Show my recent transactions"):
    st.chat_message("user").write(prompt)
    
    api_key = os.getenv("OPENAI_API_KEY")
    use_mock = os.getenv("MOCK_LLM", "true").lower() == "true" or not api_key

    with st.chat_message("assistant"):
        executed_live = False
        if not use_mock and api_key:
            try:
                llm = ChatLiteLLM(
                    model=fetch_model_config(),
                    temperature=0, streaming=True
                )
                chat_agent = ConversationalChatAgent.from_llm_and_tools(llm=llm, tools=tools, verbose=True, system_message=system_msg)
                executor = AgentExecutor.from_agent_and_tools(
                    agent=chat_agent,
                    tools=tools,
                    memory=memory,
                    return_intermediate_steps=True,
                    handle_parsing_errors=True,
                    verbose=True,
                    max_iterations=6
                )
                st_cb = StreamlitCallbackHandler(st.container(), expand_new_thoughts=False)
                response = executor(prompt, callbacks=[st_cb])
                st.write(response["output"])
                st.session_state.steps[str(len(msgs.messages) - 1)] = response["intermediate_steps"]
                executed_live = True
            except Exception as e:
                st.warning(f"Live LLM provider error: {e}. Switching to ReAct Agent Gateway...")
                executed_live = False

        if not executed_live:
            # Query the local agent API gateway which enforces guardrails and simulation
            import requests
            try:
                api_url = "http://localhost:8000/api/chat"
                res = requests.post(api_url, json={"prompt": prompt}, timeout=10)
                data = res.json()
                if data.get("status") == "blocked":
                    st.error("🛡️ **AI Guardrail Gateway: Request Blocked**")
                    st.warning(f"**Security Filter:** {data.get('reason')}")
                    st.info(data.get("response"))
                else:
                    with st.status("**ReAct Reasoning & Tool Execution**", state="complete"):
                        st.write("Evaluating user prompt against system security policy...")
                        if "action" in prompt.lower() or "union" in prompt.lower():
                            st.write("Detected tool invocation in user input. Forwarding to execution engine...")
                        else:
                            st.write("Identified current authenticated user: MartyMcFly (userId: 1)")
                            st.write("Calling tool: `GetUserTransactions(userId=1)`")
                    st.write(data.get("response"))
            except Exception as e:
                st.error(f"Error communicating with agent gateway: {e}")


display_instructions()
display_logo()


        