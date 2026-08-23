# Micromanage CLI

This is largely unfinished and hasn't really been worked on with newer features.

A typer + httpx client for the controller's REST API. Separate from
`controller/tenant_cli`, which runs inside the controller container and is for higher level actions like tenant
management

## Install

```sh
cd micromanage-cli
pip install -r requirements.txt
```

## Use

```sh
python micromanage.py login
python micromanage.py device list
python micromanage.py device info <device_id>
python micromanage.py task list
python micromanage.py stats overview
python micromanage.py yaml get groups
```
