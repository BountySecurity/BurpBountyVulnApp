"""Spring Boot Actuator endpoints - triggers 2 Spring profiles."""
import json
from flask import Blueprint, request, make_response

spring_bp = Blueprint('spring', __name__)

ACTUATOR_LINKS = {
    "_links": {
        "self": {"href": "http://localhost:8080/actuator", "templated": False},
        "health": {"href": "http://localhost:8080/actuator/health", "templated": False},
        "env": {"href": "http://localhost:8080/actuator/env", "templated": False},
        "metrics": {"href": "http://localhost:8080/actuator/metrics", "templated": False},
        "loggers": {"href": "http://localhost:8080/actuator/loggers", "templated": False},
        "heapdump": {"href": "http://localhost:8080/actuator/heapdump", "templated": False},
        "beans": {"href": "http://localhost:8080/actuator/beans", "templated": False},
        "mappings": {"href": "http://localhost:8080/actuator/mappings", "templated": False}
    }
}

ACTUATOR_ENV = {
    "activeProfiles": ["production"],
    "propertySources": [
        {
            "name": "systemProperties",
            "properties": {
                "java.runtime.name": {"value": "OpenJDK Runtime Environment"},
                "java.vm.version": {"value": "17.0.2+8"},
                "spring.datasource.url": {"value": "jdbc:mysql://db:3306/myapp"},
                "spring.datasource.username": {"value": "root"}
            }
        },
        {
            "name": "systemEnvironment",
            "properties": {
                "PATH": {"value": "/usr/local/bin:/usr/bin"},
                "HOME": {"value": "/root"},
                "DB_PASSWORD": {"value": "******"}
            }
        },
        {
            "name": "applicationConfig",
            "properties": {
                "server.port": {"value": "8080"},
                "spring.application.name": {"value": "myapp"},
                "management.endpoints.web.exposure.include": {"value": "*"}
            }
        }
    ]
}

ACTUATOR_HEALTH = {
    "status": "UP",
    "components": {
        "db": {"status": "UP", "details": {"database": "MySQL", "validationQuery": "isValid()"}},
        "diskSpace": {"status": "UP", "details": {"total": 107374182400, "free": 53687091200}},
        "redis": {"status": "UP", "details": {"version": "7.0.0"}}
    }
}

ACTUATOR_METRICS = {
    "names": [
        "jvm.memory.used", "jvm.memory.max", "system.cpu.usage",
        "process.uptime", "http.server.requests", "logback.events"
    ]
}

ACTUATOR_LOGGERS = {
    "levels": ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"],
    "loggers": {
        "ROOT": {"configuredLevel": "INFO", "effectiveLevel": "INFO"},
        "org.springframework": {"configuredLevel": "INFO", "effectiveLevel": "INFO"},
        "com.myapp": {"configuredLevel": "DEBUG", "effectiveLevel": "DEBUG"}
    }
}


def make_json(data):
    resp = make_response(json.dumps(data))
    resp.headers['Content-Type'] = 'application/json'
    return resp


@spring_bp.route('/actuator')
@spring_bp.route('/actuator/')
@spring_bp.route('/management')
@spring_bp.route('/management/')
def actuator_root():
    """Spring Boot Actuator root. Triggers: Spring_Boot_Actuators"""
    return make_json(ACTUATOR_LINKS)


@spring_bp.route('/actuator/env')
@spring_bp.route('/management/env')
@spring_bp.route('/env')
def actuator_env():
    """Actuator env endpoint."""
    return make_json(ACTUATOR_ENV)


@spring_bp.route('/actuator/health')
@spring_bp.route('/management/health')
@spring_bp.route('/health')
def actuator_health():
    return make_json(ACTUATOR_HEALTH)


@spring_bp.route('/actuator/metrics')
@spring_bp.route('/management/metrics')
@spring_bp.route('/metrics')
def actuator_metrics():
    return make_json(ACTUATOR_METRICS)


@spring_bp.route('/actuator/loggers')
@spring_bp.route('/management/loggers')
@spring_bp.route('/loggers')
def actuator_loggers():
    return make_json(ACTUATOR_LOGGERS)


@spring_bp.route('/actuator/heapdump')
@spring_bp.route('/management/heapdump')
@spring_bp.route('/heapdump')
def actuator_heapdump():
    return "Binary heap dump data...", 200


@spring_bp.route('/actuator/beans')
@spring_bp.route('/management/beans')
@spring_bp.route('/beans')
def actuator_beans():
    return make_json({"contexts": {"application": {"beans": {"dataSource": {"type": "com.zaxxer.hikari.HikariDataSource"}}}}})


@spring_bp.route('/actuator/mappings')
@spring_bp.route('/management/mappings')
@spring_bp.route('/mappings')
def actuator_mappings():
    return make_json({"contexts": {"application": {"mappings": {"dispatcherServlets": {"dispatcherServlet": []}}}}})


@spring_bp.route('/ping')
def spring_ping():
    """Springboot_Requests passive detection."""
    return make_json({"status": "OK"})
