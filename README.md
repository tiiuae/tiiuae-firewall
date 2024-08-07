# ebpf-firewall
eBPF based firewall development

## Building from Source with Nix

* Clone the repository:

```bash 
git clone https://github.com/tiiuae/ebpf-firewall.git
cd ebpf-firewall
```
* Start nix devshell
```bash
./scripts/run_dev_env.sh
```

* Build and run the project 
```bash
./scripts/run_app.sh -b <debug/release>
```