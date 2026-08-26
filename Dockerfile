    FROM python:3.12-slim
    RUN pip install langchain crewai
    ENV OPENAI_API_KEY=""
    CMD ["python", "worker.py"]