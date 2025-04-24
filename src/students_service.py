from auth_service import *
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/students/")
async def register(user: UserCreate, db: Session = Depends(get_db)):
    pass

if __name__ == "__main__":
    uvicorn.run(app, host=API_HOST, port=API_PORT_STUDENT_SERVICE)
