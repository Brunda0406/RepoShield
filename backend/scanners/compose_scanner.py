
import yaml
from pathlib import Path


def scan_compose(file_path):
    findings = []
    path = Path(file_path)

    if not path.is_file():
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "Compose file not found."
        }

    try:
        with path.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file)

    except yaml.YAMLError:
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "Invalid Docker Compose YAML."
        }

    except OSError as error:
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": str(error)
        }

    if not isinstance(config, dict):
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "Invalid Compose configuration."
        }

    services = config.get("services")

    if not isinstance(services, dict) or not services:
        return {
            "scanner": "compose_scanner",
            "status": "error",
            "total_findings": 0,
            "findings": [],
            "message": "Missing or invalid services section."
        }

    for service_name, service in services.items():

        if not isinstance(service, dict):
            findings.append({
                "service": str(service_name),
                "issue": "Invalid service configuration",
                "severity": "High",
                "recommendation": "Each service must contain a valid mapping."
            })
            continue

        if service.get("privileged") is True:
            findings.append({
                "service": service_name,
                "issue": "Privileged container enabled",
                "severity": "High",
                "recommendation": "Avoid privileged mode unless necessary."
            })

        if service.get("network_mode") == "host":
            findings.append({
                "service": service_name,
                "issue": "Host networking enabled",
                "severity": "Medium",
                "recommendation": "Use an isolated Docker network."
            })

        volumes = service.get("volumes", [])

        if isinstance(volumes, list):
            for volume in volumes:
                if isinstance(volume, str) and "docker.sock" in volume:
                    findings.append({
                        "service": service_name,
                        "issue": "Docker socket mounted into container",
                        "severity": "High",
                        "recommendation": "Avoid exposing the Docker socket."
                    })

        capabilities = service.get("cap_add", [])

        if isinstance(capabilities, list):
            for capability in capabilities:
                if str(capability).upper() == "SYS_ADMIN":
                    findings.append({
                        "service": service_name,
                        "issue": "SYS_ADMIN capability added",
                        "severity": "High",
                        "recommendation": "Remove unnecessary elevated capabilities."
                    })

        image = service.get("image", "")

        if isinstance(image, str) and image.endswith(":latest"):
            findings.append({
                "service": service_name,
                "issue": "Docker image uses the latest tag",
                "severity": "Medium",
                "recommendation": "Pin the image to a specific version or digest."
            })

    return {
        "scanner": "compose_scanner",
        "status": "completed",
        "total_findings": len(findings),
        "findings": findings
    }
