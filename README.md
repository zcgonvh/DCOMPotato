# Exploit collection for some Service DCOM Object local privalege escalation vulnerability(by SeImpersonatePrivilege abuse)

## writeup

DCOM use `RPC_C_IMP_LEVEL_IDENTIFY` as default impersonation level, for the default out-bound `IUnknown` call, see <https://learn.microsoft.com/en-us/windows/win32/com/com-security-defaults>. Of course, COM Server can override by call `CoInitializeSecurity` explicitly.

We known most windows service register their DCOM Server to provide features, [Shared Process Service](https://learn.microsoft.com/en-us/windows/win32/services/service-programs) was hosted by `svchost`, read the default impersonation level from [registry](https://www.geoffchappell.com/studies/windows/win32/services/svchost/process/index.htm).

If we pass a malicious `IUnknown` object as parameter at some DCOM call, service process will call `IRemUnknown::RemQueryInterface/RemRelease/RemAddref` on the ProxyObject, now we can got a `SecurityImpersonation` token by `CoImpersonateClient` because we are `DCOM Server` at this time.

Follow was the explicit setting `ImpersonationLevel` as `RPC_C_IMP_LEVEL_IMPERSONATE` in default installation:

```text
#after 12r2
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\print@ImpersonationLevel

#2022 only
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost\McpManagementServiceGroup@ImpersonationLevel
```

The services are `PrinterNotify` and `McpManagementService`, running as `SYSTEM`.

## build

Note this code was supports x64 and NetFX 4.x only, but you can do a little change for FX2.0/x86 compatibility(IUnknown vtbl hook, see `McpManagementPotato`).

```bash
csc /unsafe PrinterNotifyPotato.cs
csc /unsafe McpManagementPotato.cs
```

## usage

```bash
McpManagementPotato/PrinterNotifyPotato <command>
```

![](https://raw.githubusercontent.com/zcgonvh/DCOMPotato/master/images/McpManagementPotato.png)

![](https://raw.githubusercontent.com/zcgonvh/DCOMPotato/master/images/PrinterNotifyPotato.png)
 
**Thanks for [UnmarshalPwn](https://github.com/codewhitesec/UnmarshalPwn)!**

(and love my cat, Vanilla, can someone make it nekogirl?)