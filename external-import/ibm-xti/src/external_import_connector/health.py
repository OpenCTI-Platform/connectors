from datetime import datetime, timedelta, timezone
from threading import Thread
from fastapi import FastAPI
from pycti import OpenCTIConnectorHelper
import uvicorn


class HealthCheck:
    __helper: OpenCTIConnectorHelper
    __app: FastAPI

    def __init__(self, helper):
        self.__helper = helper
        self.__app = FastAPI()

    def __ping(self):
        if not self.__helper.api.health_check():
            raise ConnectionError("OpenCTI API health check failed")

        current_state = self.__helper.get_state()
        if current_state and (last_run := current_state["last_run"]):
            last_run_dt = datetime.strptime(last_run, "%Y-%m-%d %H:%M:%S")
            if last_run_dt < datetime.now() - timedelta(minutes=10):
                raise TimeoutError("Connector has not run in the last 2 intervals")

        return {'success': True}

    def __listen(self):
        self.__app.get("/health")(self.__ping)

        self.__helper.connector_logger.info("Health check listening on port 8080")
        uvicorn.run(self.__app, host="0.0.0.0", port=8080)

    def register_thread(self):
        t = Thread(target=self.__listen, daemon=True)
        t.start()
