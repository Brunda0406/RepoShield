
import yaml
from pathlib import Path


def scan_compose(file_path):
    findings = []
    path = Path(file_path)

    if not path.is_file():
        return [{
            "file": str(path),
            "issue": "Compose file not found",
            "severity": "Error",
            "recommendation": "Check the file path."
        }]

    try:
        with path.open("r", encoding="utf-8") as file:
            config = yaml.safe_load(file)

    except yaml.YAMLError:
        return [{
            "file": str(path),
            "issue": "Invalid Docker Compose YAML",
            "severity": "High",
            "recommendation": "Check and correct the YAML syntax."
        }]

    except OSError:
        return [{
            "file": str(path),
            "issue": "Unable to read Compose file",
            "severity": "Error",
            "recommendation": "Check file permissions and encoding."
        }]

    if not isinstance(config, dict):
        return [{
            "file": str(path),
            "issue": "Invalid Compose configuration",
            "severity": "High",
            "recommendation": "The YAML document must contain a mapping."
        }]

    services = config.get("services")

    if not isinstance(services, dict) or not services:
        return [{
            "file": str(path),
            "issue": "Missing or invalid services section",
            "severity": "High",
            "recommendation": "Add a valid services mapping."
        }]

    for service_name, service in services.items():

        if not isinstance(service, dict):
            findings.append({
                "file": str(path),
                "service": str(service_name),
                "issue": "Invalid service configuration",
                "severity": "High",
                "recommendation": "Each service must contain a valid mapping."
            })
            continue

        if service.get("privileged") is True:
            findings.append({
                "file": str(path),
                "service": service_name,
                "issue": "Privileged container enabled",
                "severity": "High",
                "recommendation": "Avoid privileged mode unless absolutely necessary."
            })

        if service.get("network_mode") == "host":
            findings.append({
                "file": str(path),
                "service": service_name,
                "issue": "Host networking enabled",
                "severity": "Medium",
                "recommendation": "Use an isolated Docker network where possible."
            })

        volumes = service.get("volumes", [])

        if isinstance(volumes, list):
            for volume in volumes:
                if isinstance(volume, str) and "docker.sock" in volume:
                    findings.append({
                        "file": str(path),
                        "service": service_name,
                        "issue": "Docker socket mounted into container",
                        "severity": "High",
                        "recommendation": "Avoid exposing the Docker socket to containers."
                    })

        capabilities = service.get("cap_add", [])

        if isinstance(capabilities, list):
            for capability in capabilities:
                if str(capability).upper() == "SYS_ADMIN":
                    findings.append({
                        "file": str(path),
                        "service": service_name,
                        "issue": "SYS_ADMIN capability added",
                        "severity": "High",
                        "recommendation": "Remove unnecessary elevated capabilities."
                    })

        image = service.get("image", "")

        if isinstance(image, str) and image.endswith(":latest"):
            findings.append({
                "file": str(path),
                "service": service_name,
                "issue": "Docker image uses the latest tag",
                "severity": "Medium",
                "recommendation": "Pin the image to a specific version or digest."
            })

    return findings
