import os
import requests
from typing import TypedDict, Annotated, Sequence
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool
from langchain_community.vectorstores import Chroma
from langchain_community.document_loaders import WebBaseLoader, PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langgraph.graph import StateGraph, START, END, add_messages
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import trim_messages
from pydantic import BaseModel, Field
from langchain_community.document_loaders.recursive_url_loader import RecursiveUrlLoader
from bs4 import BeautifulSoup
import sqlite3
from langgraph.checkpoint.sqlite import SqliteSaver
import uuid
import json

# 1. API Key 로드
load_dotenv()

# 2. 구조화된 출력을 위한 Pydantic 모델
class SecurityReport(BaseModel):
    vulnerability_found: bool = Field(description="보안 취약점이 발견되었는지 여부 (True 또는 False)")
    risk_level: str = Field(description="취약점의 위험도 등급 (High, Medium, Low, Safe 중 하나를 선택)")
    # 중복 선언되었던 description 필드를 하나로 병합하여 규칙을 명확히 전달합니다.
    description: str = Field(
        description="발견된 취약점에 대한 상세 분석, KISA 개발보안 가이드 및 OWASP 기준의 보안 근거를 포함하여 '반드시 한국어로 문장 형태로 작성'. "
                    "주의: Salt(솔트), Hash(해시) 등 보안 도메인의 기술 용어는 '소금'과 같이 일반 명사로 직역하지 말고 영문표기나 표준 IT 외래어를 그대로 사용할 것."
    )
    fixed_code: str = Field(description="취약점을 완벽히 방어할 수 있도록 수정된 안전한 파이썬 소스코드 예시")

# [NEW] 2-1. 사용자 의도 파악을 위한 Pydantic 모델
class IntentClassifier(BaseModel):
    intent: str = Field(
        description="사용자의 의도가 소스코드 보안 점검 및 분석 요청이면 'analysis', "
                    "단순한 인사, 이전 대화 질문, 일반적인 보안 지식 질문이면 'general'을 반환하세요."
    )

# 3. RAG 파이프라인 구성 (다중 소스 복합 인덱싱)
print("보안 가이드라인(Web + PDF) 데이터를 로드하고 인덱싱합니다. 잠시만 기다려주세요...")

secure_coding_urls = [
    "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",  # SQL 인젝션
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",  # XSS
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",  # CSRF
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",  # 인증/인가
    "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",  # 패스워드 저장(Hash/Salt)
    "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet_for_Java.html",  # JWT 보안
    "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"  # 입력값 검증
]
web_loader = WebBaseLoader(secure_coding_urls)
web_docs = web_loader.load()

# 3-2. KISA 개발보안 가이드 (PDF 로드) 
# 주의: 프로젝트 루트 폴더에 해당 PDF 파일이 있어야 합니다.
pdf_docs = []
try:
    pdf_loader = PyPDFLoader("kisa_secure_coding_guide.pdf") 
    pdf_docs = pdf_loader.load() 
except Exception as e:
    print("경고: 'kisa_secure_coding_guide.pdf' 파일이 없어 OWASP 웹 문서만 로드합니다.")

# 3-3. 문서 병합 및 분할 (Text Split) 
all_docs = web_docs + pdf_docs
text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200) 
splits = text_splitter.split_documents(all_docs) 

# 3-4. 임베딩 및 벡터 스토어 생성 
vectorstore = Chroma.from_documents(documents=splits, embedding=OpenAIEmbeddings()) 
retriever = vectorstore.as_retriever() 

print(f"총 {len(splits)}개의 보안 지식 청크가 성공적으로 인덱싱되었습니다.")

# 4. Tools 정의
@tool
def search_security_guideline(query: str) -> str:
    """OWASP 및 보안 가이드라인에서 취약점 방어 기법을 검색합니다."""
    results = retriever.invoke(query)
    return "\n".join([doc.page_content for doc in results])

@tool
def analyze_code_ast(code: str) -> str:
    """입력된 소스코드에서 위험한 패턴(예: 문자열 포매팅을 통한 SQL 조립 등)을 정적 분석합니다."""
    if "SELECT" in code.upper() and "%s" not in code and "?" not in code:
        return "경고: Prepared Statement가 적용되지 않은 SQL 쿼리가 감지되었습니다. SQL Injection 위험이 있습니다."
    return "정적 분석 결과: 특이사항 없음."

@tool
def search_cve_database(keyword: str) -> str:
    """
    특정 라이브러리, 프레임워크 또는 기술(예: sqlite3, fastapi, django)과 관련된
    최신 CVE(알려진 취약점) 정보를 NIST NVD 데이터베이스에서 실시간으로 검색합니다.
    """
    import requests

    try:
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"User-Agent": "Mozilla/5.0"}
        
        # 1. 1차 요청: 전체 결과 개수(totalResults)만 빠르게 파악하기 위해 1개만 요청
        count_response = requests.get(
            base_url, 
            params={"keywordSearch": keyword, "resultsPerPage": 1}, 
            headers=headers, 
            timeout=10
        )
        
        if count_response.status_code != 200:
            return f"CVE 검색 실패: API 응답 오류 (상태 코드 {count_response.status_code})"
            
        total_results = count_response.json().get("totalResults", 0)
        
        if total_results == 0:
            return f"'{keyword}'에 대한 CVE 취약점 정보가 없습니다."

        # 2. 2차 요청: 가장 최신 데이터를 가져오기 위해 마지막 페이지로 점프
        start_index = max(0, total_results - 3)
        latest_response = requests.get(
            base_url, 
            params={"keywordSearch": keyword, "resultsPerPage": 3, "startIndex": start_index}, 
            headers=headers, 
            timeout=10
        )
        
        vulnerabilities = latest_response.json().get("vulnerabilities", [])

        # 3. 추출한 최신 데이터를 발행일(published) 기준으로 내림차순(최신순) 한 번 더 정렬
        vulnerabilities.sort(
            key=lambda x: x.get("cve", {}).get("published", ""), 
            reverse=True
        )

        results = []
        for v in vulnerabilities:
            cve_item = v.get("cve", {})
            cve_id = cve_item.get("id", "Unknown ID")
            published_date = cve_item.get("published", "N/A")[:10]  # YYYY-MM-DD 포맷 추출
            
            # 영문 설명 추출
            descriptions = cve_item.get("descriptions", [])
            desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "설명 없음")

            # CVSS Score (위험도 점수) 추출
            metrics = cve_item.get("metrics", {})
            cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
            base_score = cvss[0].get("cvssData", {}).get("baseScore", "N/A") if cvss else "N/A"

            # 결과 문자열에 발행일을 추가하여 최신 데이터임을 명시적으로 보여줌
            results.append(f"- {cve_id} (발행일: {published_date}, 위험도: {base_score}): {desc_text}")

        return f"[{keyword} 관련 최신 CVE 정보]\n" + "\n".join(results)

    except requests.exceptions.Timeout:
        return "CVE 검색 시간 초과: 현재 NVD 서버 응답이 지연되고 있습니다."
    except Exception as e:
        return f"CVE 검색 중 오류 발생: {str(e)}"

tools = [search_security_guideline, analyze_code_ast, search_cve_database]
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
llm_with_tools = llm.bind_tools(tools)

# 5. LangGraph State 정의 (응답 타입 구분 플래그 추가)
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    report: SecurityReport
    final_response_type: str  # 'report' 또는 'chat'을 기록

# 6. Middleware (가드레일 역할)
def guardrail_middleware(state: AgentState):
    last_message = state["messages"][-1].content
    if "해킹해줘" in last_message or "공격코드" in last_message:
        return {"messages": [AIMessage(content="[시스템 차단] 악의적인 해킹 요청은 처리할 수 없습니다.")]}
    return {"messages": []}

# 7. Agent Node
def agent_node(state: AgentState):
    system_instruction = SystemMessage(
        content="""당신은 KISA 소프트웨어 개발보안 가이드 및 OWASP Top 10을 기준으로 코드를 점검하는 대한민국 최고의 정보보안 전문가입니다. 
        모든 설명은 친절하고 전문적인 한국어로 작성하되, 아래의 [용어 사용 규칙]을 엄격히 준수하세요.
        
        [용어 사용 규칙]
        1. Salt, Rainbow Table, Hash, SQL Injection, Cross-Site Scripting 등의 정보보안 전문 기술 용어는 절대 일상 용어로 직역(예: 소금, 무지개 식탁 등)하지 마세요.
        2. 전문 용어는 가급적 영어 원문을 그대로 기재하거나, 통용되는 외래어 표기(예: 솔트, 레인보우 테이블)를 사용하세요.
        3. 약어 사용 시 최초 1회는 풀네임을 병기하세요."""
    )
    
    # [추가됨] 메시지 트리밍 로직 (메모리 관리)
    # LLM의 컨텍스트 윈도우 초과 및 API 비용 증가를 방지하기 위해 최근 대화만 유지합니다.
    # 단, 히스토리 복원을 위해 저장된 'REPORTSERIALIZED:' 메시지는 LLM의 판단에 방해가 되므로 제외하고 전달합니다.
    filtered_messages = [
        msg for msg in state["messages"] 
        if not (isinstance(msg, AIMessage) and msg.content.startswith("REPORTSERIALIZED:"))
    ]

    trimmed_history = trim_messages(
        filtered_messages,
        max_tokens=3000,        # 유지할 최대 토큰 수 (GPT-4o-mini 기준 3000이면 충분한 맥락 유지)
        strategy="last",        # 가장 최신('last') 메시지부터 보존하여 과거로 역산
        token_counter=llm,      # 이미 선언해둔 ChatOpenAI 객체(llm)를 이용해 정확한 토큰 수 계산
        include_system=False    # 시스템 프롬프트는 아래에서 따로 붙이므로 제외
    )
    
    # 시스템 프롬프트 뒤에 '잘라낸' 최신 대화 기록만 이어붙여 모델에 전달
    messages = [system_instruction] + trimmed_history
    response = llm_with_tools.invoke(messages)
    
    return {"messages": [response]}

# 8. 구조화된 출력 Node (소스코드 분석 리포트용)
def output_parser_node(state: AgentState):
    structured_llm = llm.with_structured_output(SecurityReport)
    
    parser_instruction = SystemMessage(
        content="""앞서 수행한 보안 분석 내용을 바탕으로 최종 SecurityReport 스키마에 맞는 리포트를 생성하세요. 
        
        [작성 지침]
        1. description 필드의 모든 내용은 반드시 완성된 한국어 문장으로 작성되어야 합니다.
        2. 단, Salt, Hash, Rainbow Table, SQL Injection 등 정보보안 전문 기술 용어는 절대 '소금', '무지개 테이블'과 같이 일상 용어로 직역하지 마세요.
        3. 전문 용어는 반드시 영어 원문 그대로 표기하거나, 실무에서 통용되는 IT 표준 외래어(예: 솔트, 해시 등)를 유지하여 보고서의 전문성을 보장하세요."""
    )
    
    # 'REPORTSERIALIZED:' 메시지가 포함되어 있으면 invoke 시 에러가 날 수 있으므로 제외
    filtered_messages = [
        msg for msg in state["messages"] 
        if not (isinstance(msg, AIMessage) and msg.content.startswith("REPORTSERIALIZED:"))
    ]
    
    report = structured_llm.invoke([parser_instruction] + filtered_messages)
    
    # [복구 기능용] 리포트 데이터를 JSON으로 직렬화하여 메시지 기록에 남깁니다.
    serialized_report = f"REPORTSERIALIZED:{json.dumps(report.model_dump(), ensure_ascii=False)}"
    
    return {
        "report": report, 
        "messages": [AIMessage(content=serialized_report)],
        "final_response_type": "report"
    }

# [NEW] 8-1. 일반 대화 처리 Node
def general_chat_node(state: AgentState):
    # LLM이 이미 agent_node에서 챗봇 형태로 응답(AIMessage)을 생성했으므로,
    # 여기서는 최종 응답 타입이 'chat'이라는 것만 상태에 기록합니다.
    return {"final_response_type": "chat"}

# [CHANGED] 9. 조건 분기 로직 (의도 분류 기반 스마트 라우팅)
def route_intent(state: AgentState) -> str:
    messages = state["messages"]
    last_message = messages[-1]
    
    # 가드레일 차단 시 즉시 종료
    if "[시스템 차단]" in last_message.content:
        return "end"
    
    # Tool 호출이 필요하면 action 노드로 이동
    if last_message.tool_calls:
        return "continue"
    
    # Tool 호출이 끝났거나 필요 없는 경우, 사용자의 전체 대화 문맥을 보고 의도를 판단
    classifier = llm.with_structured_output(IntentClassifier)
    intent_result = classifier.invoke(messages)
    
    if intent_result.intent == "analysis":
        return "parse_output"  # 코드 분석 리포트 출력
    else:
        return "general_chat"  # 일반 챗봇 대화

# 10. Graph 구성
workflow = StateGraph(AgentState)

workflow.add_node("guardrail", guardrail_middleware)
workflow.add_node("agent", agent_node)

from langgraph.prebuilt import ToolNode
workflow.add_node("action", ToolNode(tools))
workflow.add_node("parser", output_parser_node)
workflow.add_node("general_chat", general_chat_node) # 일반 챗봇 노드 추가

workflow.add_edge(START, "guardrail")
workflow.add_edge("guardrail", "agent")

# 변경된 분기 로직(route_intent) 연결
workflow.add_conditional_edges(
    "agent",
    route_intent,
    {
        "continue": "action",
        "parse_output": "parser",
        "general_chat": "general_chat",
        "end": END
    }
)
workflow.add_edge("action", "agent") 
workflow.add_edge("parser", END)
workflow.add_edge("general_chat", END) # 일반 대화도 종료로 연결

conn = sqlite3.connect("agent_memory.db", check_same_thread=False)
memory = SqliteSaver(conn)

# 2. 대화 기록을 저장할 내부 테이블 세팅 (최초 1회만 알아서 생성됨)
memory.setup()

# 3. 에이전트 그래프 컴파일
app_graph = workflow.compile(checkpointer=memory)