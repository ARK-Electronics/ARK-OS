OVERVIEW:
You are in a github repo. This repo has submodules. This project contains scripts, source code, and other files for the ARK-OS software stack that gets installed on our Jetson Orin Nano/NX carrier board and our Pi6X Flow board. These boards are Pixhawk PAB + companion computer carrier boards. The ARK-OS repo is a collection of scripts and services intended to work on our carrier boards to enhance their functionality and improve user experience. Please always read the README first.

EXPECTATIONS:
- You will always strive to K.I.S.S
- You will be cognizant of your limitations. Ask for help or more information when you are unsure.
- You will use the ARK color scheme when working on Vue files.
- You will not provide README or "integration guides" for things unless I explicitly ask.
- You will be judicious with comments. Do not comment on things that are self explanatory.
- You will follow the XDG Base Directory specification for services. Keep in mind this means typical services run in user space, therefore you must think about any additional permissions the files will need. For example network operations require sudo.

THE CURRENT TASK:
You will be helping me implement the "connection-manager" service. This service is a microservice which provides a REST API for performing network and modem related connection management. This service is interacted with from the ARK-UI which is hosted locally. I've already worked with Claude previously at implementing this task. Previously Claude got a bit confused and didn't implement things how I asked. What I want is a python based connection-manager program. It will handle all of the connection management tasks. Please look at the exising bash scripts in platform/common/scripts/ for the connection management operations. I wrote this scripts and tested them, so they are the gold standard for functionality. I want you to implement the same functionality but in the python program. You can use whatever tools fit best for the job, but it's important to always compare your implementation to my bash scripts to ensure you're accomplishing the same tasks and producing the same results. I don't want you to try to test any code or run anything. I want you to review the current state of things and improve/fix as we go. I will be prompting you further in our chat.

Here are the files that the last Claude created (btw you could also use git diff to check since I have not yet committed anything):
manifests/connections-manager.manifest.json
platform/common/scripts/connections_manager.toml
platform/common/scripts/connections_manager_service.py
platform/common/services/connections-manager.service
scripts/install_connections_manager.sh
ark-ui/src/components/NetworkPage.vue
ark-ui/src/services/
