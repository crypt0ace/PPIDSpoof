## PPID Spoofing and Blocking DLLs in C#
Using `InitializeProcThreadAttributeList` and `UpdateProcThreadAttribute` to update attributes of the process to change parent PID and add `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`.

## Demo:
![Demo Attributes](/assets/svchost_attributes.png)
<br>
![Demo DLLs](/assets/svchost_dlls.png)
<br>
Look at the blog [here](https://crypt0ace.github.io/posts/Staying-under-the-Radar/) to understand what is happening. 

## TODO:
- [ ] Figure out a way to make the process window hidden if the process doesnt exist already. 
