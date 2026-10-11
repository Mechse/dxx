# dxx

ssh over the doxx.net mesh, plus the tools to get a server there and lock it down. One binary.

```sh
dxx connect           # this Mac joins the doxx mesh
dxx up root@203.0.113.10 --as hetzner
dxx lock hetzner      # public SSH closed
dxx hetzner           # ssh, but over doxx
```

## Getting started

1. **Build and install dxx.**

   ```sh
   go build -o dxx . && sudo install dxx /usr/local/bin/
   ```

2. **Install WireGuard** (used by `dxx connect` to bring the tunnel up on this Mac).

   ```sh
   brew install wireguard-tools
   ```

3. **Save a doxx token.** In the portal: Account → Auth Tokens → role net-admin, expiry 7–30 days. Copy it, then:

   ```sh
   mkdir -p ~/.config/doxx
   pbpaste > ~/.config/doxx/token && chmod 600 ~/.config/doxx/token
   ```

   The token can also come from `DOXX_TOKEN` / `DOXX_TOKEN_FILE`. It is never sent to the server or printed.

4. **Put this Mac on the mesh.** Asks for your sudo password.

   ```sh
   dxx connect
   dxx tunnels           # your Mac's tunnel and mesh IP should be listed
   ```

5. **Put a server on the mesh** and give it a name. dxx picks the doxx location closest to the server; `--server` (see `dxx servers`) chooses one yourself. If the server asks for a password, you type it once and dxx offers to install your SSH key so it never asks again.

   ```sh
   dxx up root@203.0.113.10 --as hetzner
   ```

6. **Log in over the mesh.**

   ```sh
   dxx hetzner
   ```

7. **Close public SSH** once step 6 works.

   ```sh
   dxx lock hetzner
   ```

8. **Leave the mesh** when you're done. `dxx connect` brings you back.

   ```sh
   dxx disconnect
   ```

## This Mac

```sh
dxx connect       # creates/reuses a tunnel for this Mac, writes the config, brings it up
dxx disconnect
```

What `connect` does:

1. **Tunnel**: reuses the one named `dxx-<hostname>`, or creates it on the fastest location (it pings them all once, about 15s).

   ```sh
   dxx connect --name macbook                          # choose the tunnel name
   dxx connect --server wireguard.fra.eu.doxx.net      # choose the location
   ```

2. **Config**: the same mesh-only one servers get. Only `10.0.0.0/8` and `2602:f5c1::/36` go through doxx; your internet traffic and DNS are untouched. Written to `~/.config/doxx/dxx.conf` (600).

   ```sh
   dxx connect --dry-run                               # show the plan, change nothing
   ```

3. **Up**: runs `sudo wg-quick up ~/.config/doxx/dxx.conf` and waits for the handshake. Running it while connected changes nothing.

   ```sh
   sudo wg show                                        # interface, peer, last handshake
   ```

`disconnect` runs `wg-quick down` and removes the config:

```sh
dxx disconnect
dxx disconnect --delete-tunnel    # also delete the tunnel from your doxx account
```

After the first `connect`, `dxx up` allows this Mac automatically; `--allow-from` is only needed for another device. Don't run the doxx.net app's VPN at the same time: both would claim the mesh routes.

## Tunnels and rules

```sh
dxx tunnels                           # NAME  SERVER  MESH IP
dxx tunnels rm <name>...              # delete tunnels, with their firewall rules (asks first; --yes)
dxx rules                             # who may reach which tunnel
dxx rules dxx-hetzner                 # only the rules of one tunnel
dxx rules rm dxx-hetzner macbook      # stop letting "macbook" in (tunnel name or IP)
dxx rules rm dxx-hetzner all          # remove every rule of that tunnel
dxx rules rm dxx-hetzner all --port 22
```

`tunnels rm` works on any tunnel in your account, also ones from the portal or the doxx.net app. It refuses a tunnel that a saved server or this Mac is using and tells you the command that removes it properly (`dxx down <name> --delete-tunnel`, `dxx disconnect --delete-tunnel`); `--force` deletes it anyway. Saved server names are removed with `dxx forget <name>`.

## Starting over

```sh
dxx reset --dry-run   # list what would be removed
dxx reset             # asks you to type "reset"; --yes skips the question
```

`reset` undoes everything dxx set up, in this order:

1. **Servers**: each saved server is unlocked, its `doxx0` interface and config are removed, and its tunnel and firewall rules are deleted from your doxx account.
2. **This Mac**: disconnected, and its tunnel deleted.
3. **Files**: `dxx-hosts.json`, `dxx-local.json` and `dxx.conf` in `~/.config/doxx/`.

It only deletes tunnels dxx itself created; ones from the portal or the doxx.net app stay. It also keeps your token, your SSH key on the servers and installed packages (`wireguard-tools`, `nftables`).

If a server can't be reached, it is skipped and kept, and so are this Mac's tunnel and connection: a locked server is only reachable through them. Fix the server (or unlock it from the provider's web console), then run `dxx reset` again.

## Names

Give a server a name once, then use the name everywhere: `dxx hetzner`, `dxx lock hetzner`, `dxx unlock hetzner`, `dxx down hetzner`.

```sh
dxx up root@203.0.113.10 --as hetzner                       # name it while setting up
dxx name hetzner root@203.0.113.10                          # or name any server later
dxx name box hetzner                                        # rename
dxx ls                                                      # NAME  SSH HOST  MESH IP
dxx forget box                                              # drop the name (server untouched)
dxx deploy@hetzner                                          # same server, different user
```

Names are stored in `~/.config/doxx/dxx-hosts.json`. A `Host` alias from your `~/.ssh/config` works as well.

## Connecting

Anything that isn't a subcommand goes to ssh, with the same arguments:

```sh
dxx hetzner                          # interactive shell
dxx hetzner uptime                   # run a command
dxx -L 5432:localhost:5432 hetzner   # port forward, e.g. Postgres
dxx -- up                            # a host literally called "up"
```

dxx finds the server's mesh IP (saved by `up`/`lock`, or looked up by tunnel name in your doxx account) and runs
`ssh -o HostName=<mesh-ip> -o HostKeyAlias=<public-host> <your-host> ...`.
Your `~/.ssh/config` (user, keys, port) still applies and the known host key is reused, so there's no new fingerprint prompt, but packets only travel over doxx. If the mesh IP doesn't answer within 4s, dxx says why instead of hanging.

For scp, rsync or VS Code Remote, add the `~/.ssh/config` block that `dxx lock` prints and use that alias (`scp file hetzner-doxx:`).

## dxx up

1. **Login**: one SSH connection is opened and reused for every step, so a password is asked for at most once. On a password login dxx offers to add your public key to the server's `authorized_keys` (`--no-copy-key` skips the question).
2. **Preflight** over SSH: root/sudo, WireGuard installed, existing WireGuard/doxx interfaces (refuses unless `--force`), existing `10.x` routes.
3. **Tunnel**: reuses one with the same name, or creates it on `--server`. Without `--server` the server pings the doxx locations and the closest one is used. With `--as hetzner` the tunnel is called `dxx-hetzner`.
4. **Config** rewritten for a remote server: `AllowedIPs` = doxx mesh only (`10.0.0.0/8`, `2602:f5c1::/36`), no `DNS =`, no hooks, keepalive 25. Default route, public SSH and the resolver stay untouched.
5. **doxx firewall**: allows TCP 22 from your Mac's tunnel IP (the `dxx connect` tunnel, or `--allow-from`) to the server's mesh IP.
6. **Server**: installs `wireguard-tools`, writes `/etc/wireguard/doxx0.conf` (600), enables `wg-quick@doxx0`, waits for the handshake.
7. Optional `--terminfo xterm-ghostty`.

Idempotent: running it again reuses the tunnel and rule.

## dxx lock / unlock

`lock` makes the server accept SSH only through doxx:

1. Checks the tunnel is up, then **logs in over the mesh first**. If that fails, it stops and changes nothing.
2. Arms a **rollback timer** on the server (default 5 min, `--confirm`) that removes the lock automatically.
3. Installs a small nftables table (`inet dxx`) that drops new SSH connections on every interface except `lo` and `doxx0`, loaded at boot by `dxx-lock.service`. Established sessions are kept. If UFW is active, it also allows SSH on `doxx0`.
4. Opens a **fresh** mesh SSH session and only then disarms the rollback. If that fails, public SSH comes back by itself.
5. Checks from your Mac that the public port is really closed.

`--all` drops all new public inbound traffic, not just SSH (web servers become mesh-only too). `--ports 22,2222` picks the ports.

`unlock` removes it again, over the mesh (falls back to public SSH). Emergency, from the Hetzner web console:

```sh
systemctl disable --now dxx-lock.service; nft delete table inet dxx
```

`dxx down` refuses to remove the tunnel while the server is locked.

## All commands

```
dxx [ssh options] <name|host> [command]
dxx ls | name <name> <ssh-host> | forget <name>
dxx connect    [--server LOC] [--name TUNNEL] [--dry-run]
dxx disconnect [--delete-tunnel]
dxx reset      [--yes] [--dry-run]
dxx up     <ssh-host|name> --as NAME [--server LOC] [--name TUNNEL] [--allow-from T] [--terminfo TERM] [--no-copy-key] [--dry-run] [--force] [--debug]
dxx lock   <name> [--all] [--ports 22] [--confirm 300] [--dry-run]
dxx unlock <name> [--mesh-ip IP]
dxx down   <name> [--delete-tunnel]
dxx servers | tunnels | rules [tunnel]
dxx tunnels rm <name>... [--yes] [--force]
dxx rules rm   <tunnel> <from|all> [--port N]
```

`--debug` prints API responses with keys and tokens redacted.

## Notes

- Mesh SSH only works while doxx is connected on your Mac (`dxx connect`). Keep the Hetzner web console as the last resort.
- The Hetzner **cloud** firewall is separate. `lock` doesn't touch it; the server-side lock is enough on its own.
- The same applies to your Mac: on a `10.x` LAN, mesh peers inside that LAN's range aren't reachable; `connect` warns about this.
- If the server is in a Hetzner private network (`10.0.0.0/16` etc.), mesh peers inside that range won't be reachable; `up` warns about this.
