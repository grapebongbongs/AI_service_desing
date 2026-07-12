import uuid
import time
import json
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from agent import app_graph
from langchain_core.messages import HumanMessage, AIMessage

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

# =====================================================================
# 세션 TTL(자동 만료) 관리를 위한 메모리 스토어 및 제한 시간 설정
# =====================================================================
SESSION_ACCESS_LOG = {}
TTL_SECONDS = 3600  # 1시간 (3600초) 초과 시 세션 만료 처리 

class ChatRequest(BaseModel):
    message: str
    session_id: str

# [수정 포인트 1] SqliteSaver 충돌 방지를 위해 async def -> def 로 변경
@app.post("/api/chat")
def chat_endpoint(request: ChatRequest):
    current_time = time.time()
    current_session = request.session_id.strip()
    
    # 1. 최초 접속 시 빈 세션 ID가 들어오면 새로 발급
    if not current_session:
        current_session = str(uuid.uuid4())
        
    # 2. TTL (자동 만료) 검사 로직
    if current_session in SESSION_ACCESS_LOG:
        last_access_time = SESSION_ACCESS_LOG[current_session]
        # 마지막 대화 시간으로부터 TTL_SECONDS 이상 지났는지 확인
        if current_time - last_access_time > TTL_SECONDS:
            # 제한 시간이 지났다면 기존 세션 ID를 버리고 새로 발급 (기존 기억 리셋)
            current_session = str(uuid.uuid4())
            print(f"[TTL 만료] 제한 시간이 경과하여 새로운 세션({current_session})으로 리셋됩니다.")
    
    # 3. 현재 접속 시간을 갱신하여 타이머 초기화
    SESSION_ACCESS_LOG[current_session] = current_time

    # 4. LangGraph 에이전트 실행 
    config = {"configurable": {"thread_id": current_session}}
    inputs = {"messages": [HumanMessage(content=request.message)]}
    
    # [수정 포인트 2] await ainvoke -> invoke 로 변경하여 동기식 DB와 호환성 확보
    result = app_graph.invoke(inputs, config=config)
    
    response_type = result.get("final_response_type")
    
    # 5. 프론트엔드로 응답과 함께 (유지되거나 갱신된) session_id를 돌려줌
    if response_type == "report" and "report" in result:
        return {
            "type": "report", 
            "data": result["report"].model_dump(),
            "session_id": current_session
        }
    else:
        return {
            "type": "text", 
            "data": result["messages"][-1].content,
            "session_id": current_session
        }

@app.get("/", response_class=HTMLResponse)
async def root():
    with open("static/index.html", "r", encoding="utf-8") as f:
        return f.read()
    
# [수정 포인트 3] DB 읽기 작업이 포함되므로 안전하게 동기 함수(def)로 변경
@app.get("/api/history/{session_id}")
def get_history(session_id: str):
    """프론트엔드가 처음 켜질 때 과거 대화 기록을 요청하는 엔드포인트"""
    config = {"configurable": {"thread_id": session_id}}
    
    # LangGraph의 상태(State)를 SQLite DB에서 꺼내옵니다.
    state = app_graph.get_state(config)
    
    # 만약 해당 세션에 저장된 기록이 없다면 빈 리스트 반환
    if not state or not state.values:
        return {"history": []}
        
    messages = state.values.get("messages", [])
    
    # 프론트엔드가 화면에 그리기 쉽도록 역할(role)과 내용(content) 포맷팅
    history_data = []
    for msg in messages:
        if isinstance(msg, HumanMessage):
            history_data.append({"role": "user", "content": msg.content})
        elif isinstance(msg, AIMessage):
            # [복구 기능] 저장된 메시지가 직렬화된 리포트인지 확인
            if msg.content.startswith("REPORTSERIALIZED:"):
                try:
                    report_json = msg.content.replace("REPORTSERIALIZED:", "", 1)
                    report_data = json.loads(report_json)
                    history_data.append({"role": "report", "content": report_data})
                except Exception as e:
                    print(f"리포트 복원 중 오류: {e}")
            # 도구 호출 기록 등은 제외하고 실제 답변만 화면에 표시
            elif msg.content:
                history_data.append({"role": "ai", "content": msg.content})

    return {"history": history_data}