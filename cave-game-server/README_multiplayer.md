# Cave Game multiplayer

There are two ways to play together. Pick one.

## A. Live room (no server, nothing to install)
Open the published Cave Game page, press **Multiplayer**, type any room code and press **Join live room**.
Everyone who types the same code gets the same world (the code is the world seed) and sees each other.
Chat with **T**. Block edits, doors, TNT craters and so on are shared.

Limits (set by the claude.ai room feature, not the game):
* Only people who are signed in AND allowed to open the artifact can join (your organisation, or people you invited). A public link cannot connect.
* A player who joins late sees the last ~40 block edits of each other player, not the whole history. Use option B if you need the full history.

## B. Your own WebSocket server
1. Install Node 18+.
2. Put `server.js` and `cavegame.html` in one folder, then:
   ```
   npm init -y
   npm i ws
   node server.js
   ```
3. Open `http://localhost:8080`, press **Multiplayer**, the server box is pre-filled (`ws://localhost:8080`), type a room code and press **Join** on the server row.

### Putting it on the internet over port 443 (works on most school Wi-Fi)
Hosts such as Render, Railway, Fly.io, Glitch or a small VPS terminate HTTPS for you:
* Start command `node server.js`, it reads the `PORT` the host gives it.
* Your address is `https://your-app.example.com`; players open that address, and the game connects to `wss://your-app.example.com` on port 443, which looks like ordinary HTTPS traffic.
* Serve the page from the same address (the server does this when `cavegame.html` is next to it). A page opened from claude.ai cannot reach outside servers, so use the page from your own address for option B.
* Keep the address plain (no odd ports). Some filters block unknown domains, so a normal-looking domain helps.

### Built to stay light on a Chromebook
* Player state is sent at 10 times a second and only when something changed, as one small message per tick.
* Block edits are batched and de-duplicated per block.
* At most 14 other players are drawn, with interpolation, and far ones are skipped.
* The game lowers view distance and resolution by itself if the frame rate stays low.
