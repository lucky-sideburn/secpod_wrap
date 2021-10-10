# secpod_wrap

## Description

A small Python utility for wrapping some CNCF tools.

At moment it wraps [Trivy](https://github.com/aquasecurity/trivy) of Aqua Security, store on SQLite CVE of running pods, reports their owners (Jobs, StatefulSets, Deployments,...)

## Usage

### Store on SQLite a vulnerability detection related to running pods

```bash
export K8S_TOKEN="..."
export K8S_URL="https://192.168.58.99:6443"

./secpod_wrap.py store
```

### List images, pods and their owners (Jobs, StatefulSets, Deployments,...)

```bash
export K8S_TOKEN="..."
export K8S_URL="https://192.168.58.99:6443"

./secpod_wrap.py images
```

### List found vulnerabilities

```bash
export K8S_TOKEN="..."
export K8S_URL="https://192.168.58.99:6443"

./secpod_wrap.py vulns
```

### Help

```bash
./secpod_wrap.py --help
```

## Example

### Store

```bash
luckysideburn:~/WORK/secpod_wrap$ ./secpod_wrap.py store
Clean old records of images
Clean old records of cve
Looking for pods running on all namespaces
Scan nginx:1.14.2
CVE-2021-3712 already stored
Scan luckysideburn/kubeinvaders:develop
CVE-2018-12886 already stored
Save record for rancher/klipper-helm:v0.6.4-build20210813
Images scanning completed
```

### List Images

```bash
luckysideburn:~/WORK/secpod_wrap$ ./secpod_wrap.py images
[
    {
        "image": "nginx:1.14.2",
        "container": "nginx",
        "pod": "nginx-deployment-66b6c48dd5-7p2bj",
        "owner": "nginx-deployment",
        "owen_kind": "Deployment",
        "namespace": "namespace2"
    }
]
[
    {
        "image": "nginx:1.14.2",
        "container": "nginx",
        "pod": "nginx-deployment-66b6c48dd5-7p2bj",
        "owner": "nginx-deployment",
        "owen_kind": "Deployment",
        "namespace": "namespace2"
    }
]
```

### List Vulns

```bash
luckysideburn:~/WORK/secpod_wrap$ ./secpod_wrap.py vulns
{
    "cve": [
        {
            "image": "nginx:1.14.2",
            "cve_id": "CVE-2016-2779",
            "installed_version": "2.29.2-1+deb9u1",
            "primary_url": "https://avd.aquasec.com/nvd/cve-2016-2779",
            "severity": "HIGH",
            "owners": [
                {
                    "owner": "nginx-deployment",
                    "owner_kind": "Deployment",
                    "namespace": "namespace2"
                },
                {
                    "owner": "nginx-deployment",
                    "owner_kind": "Deployment",
                    "namespace": "namespace1"
                }
            ]
        },
        {
            "image": "nginx:1.14.2",
            "cve_id": "CVE-2018-12886",
            "installed_version": "6.3.0-18+deb9u1",
            "primary_url": "https://avd.aquasec.com/nvd/cve-2018-12886",
            "severity": "HIGH",
            "owners": [
                {
                    "owner": "nginx-deployment",
                    "owner_kind": "Deployment",
                    "namespace": "namespace2"
                },
                {
                    "owner": "nginx-deployment",
                    "owner_kind": "Deployment",
                    "namespace": "namespace1"
                }
            ]
        }
    ]
}
```