// atomwall live visitor globe. Renders with the vendored globe.gl + three.js
// (webui/vendor/, see CLAUDE.md) — no CDN fetch at runtime: every visitor of
// every site this is embedded on would otherwise leak their IP to that CDN
// on page load, defeating the whole point of the anonymized data contract
// below. Same technique as https://globe.gl/example/clouds/ (Blue Marble +
// topology bump map + atmosphere + a manually-added, independently-rotating
// cloud sphere), vendored locally instead of loaded from jsdelivr/esm.sh.
//
// Used in two places:
//   1. Admin dashboard (webui/index.html): loaded plain, mounted explicitly
//      via window.AtomwallGlobe.mount(container, opts).
//   2. Public embed, on the protected site itself: loaded with a
//      data-atomwall-globe attribute on the <script> tag, and self-mounts
//      into #atomwall-globe (or an auto-created container) using the
//      script's own origin as the API base. globe_server.cpp additionally
//      serves /vendor/* (JS + textures) on this listener so the embed works
//      standalone, without reaching into the loopback admin static server.
//
// Data contract (see history/globe_event_log.hpp, admin/json_view.cpp):
// every event is {seq, timestamp, lat, lon, blocked} — no IP, no
// user-agent, no path, nothing identifying. That's a structural guarantee
// upstream of this file, not something this file has to enforce.
(() => {
  "use strict";

  // Captured synchronously — document.currentScript is only valid while this
  // script is the one executing, including for `async` scripts, as long as
  // it's read at the top level rather than inside a later callback.
  const SELF_SCRIPT = document.currentScript;
  const VENDOR_BASE = new URL(".", SELF_SCRIPT.src).href + "vendor/";

  const GREEN = "#3ecf8e";
  const RED = "#ff6161";
  const ARC_LIFETIME_MS = 1600;
  const ARC_DASH_ANIMATE_MS = 1500;
  const CLOUDS_ALTITUDE = 0.006;
  const CLOUDS_ROTATION_SPEED_DEG = -0.006; // per frame, matches the reference example

  // Loaded once per page and shared by every mount() call (e.g. an
  // admin-dashboard mount plus a public-embed auto-mount can't both happen
  // on the same page today, but this stays correct if that changes).
  // Resolves with a THREE namespace once both vendored scripts are loaded.
  //
  // Loads three.js (a classic UMD build — it only knows how to attach
  // itself as `window.THREE`) first, captures that reference for our own
  // cloud-mesh layer below, then deletes `window.THREE` again before
  // loading globe.gl. globe.gl checks for a global THREE at its own
  // module-init time and, if it finds one, expects a specific newer API
  // surface (THREE.Timer) this vendored build predates, which crashes it
  // outright — hiding the global lets it fall back to its own internal
  // minimal stub instead, which is all it actually needs. This is exactly
  // what the reference example (globe.gl/example/clouds) gets too: it only
  // ever imports THREE as a *local* ES module, so window.THREE is never set
  // there either.
  let globePromise = null;
  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const el = document.createElement("script");
      el.src = src;
      el.onload = () => resolve();
      el.onerror = () => reject(new Error("failed to load " + src));
      document.head.appendChild(el);
    });
  }
  function ensureGlobeLibrary() {
    if (!globePromise) {
      globePromise = loadScript(VENDOR_BASE + "three.min.js").then(() => {
        const THREE = window.THREE;
        delete window.THREE;
        return loadScript(VENDOR_BASE + "globe.gl.min.js").then(() => THREE);
      });
    }
    return globePromise;
  }

  function mount(container, opts) {
    opts = opts || {};
    const snapshotUrl = opts.snapshotUrl;
    const streamUrl = opts.streamUrl;

    let destroyed = false;
    let world = null;
    let cloudsMesh = null;
    let serverLoc = null;
    let activeArcs = [];
    let eventSource = null;
    let resizeObserver = null;

    function spawnArc(event) {
      if (!serverLoc || destroyed) return; // no arc endpoint yet — dropped, the next event will likely have one
      activeArcs.push({
        startLat: event.lat,
        startLng: event.lon,
        endLat: serverLoc.lat,
        endLng: serverLoc.lon,
        color: event.blocked ? RED : GREEN,
        createdAt: performance.now(),
      });
      if (activeArcs.length > 200) activeArcs.splice(0, activeArcs.length - 200);
      if (world) world.arcsData(activeArcs);
    }

    function pruneArcs() {
      if (destroyed) return;
      const now = performance.now();
      const before = activeArcs.length;
      activeArcs = activeArcs.filter((arc) => now - arc.createdAt < ARC_LIFETIME_MS);
      if (world && activeArcs.length !== before) world.arcsData(activeArcs);
    }
    const pruneTimer = setInterval(pruneArcs, 400);

    function resize() {
      if (!world) return;
      world.width(Math.max(1, container.clientWidth));
      world.height(Math.max(1, container.clientHeight));
    }

    async function connect() {
      if (snapshotUrl) {
        try {
          const res = await fetch(snapshotUrl);
          if (res.ok) {
            const snapshot = await res.json();
            if (snapshot.server_location) serverLoc = snapshot.server_location;
            (snapshot.events || []).slice(-40).forEach((event, i) => {
              setTimeout(() => spawnArc(event), i * 60);
            });
          }
        } catch (err) {
          console.warn("atomwall globe: snapshot fetch failed", err);
        }
      }
      if (streamUrl && typeof EventSource !== "undefined") {
        eventSource = new EventSource(streamUrl);
        eventSource.onmessage = (message) => {
          try {
            spawnArc(JSON.parse(message.data));
          } catch (err) {
            // malformed frame — ignore, next one will likely be fine
          }
        };
      }
    }

    ensureGlobeLibrary()
      .then((THREE) => {
        if (destroyed) return;

        world = new Globe(container, { animateIn: false })
          .backgroundColor("rgba(0,0,0,0)")
          .globeImageUrl(VENDOR_BASE + "earth-color.webp")
          .bumpImageUrl(VENDOR_BASE + "earth-topology.webp")
          .showAtmosphere(true)
          .atmosphereColor("#5b8cff")
          .atmosphereAltitude(0.2)
          .arcColor("color")
          .arcAltitude(0.22)
          .arcStroke(0.55)
          .arcDashLength(0.4)
          .arcDashGap(0.25)
          .arcDashAnimateTime(ARC_DASH_ANIMATE_MS)
          .arcsData(activeArcs);

        world.controls().autoRotate = true;
        world.controls().autoRotateSpeed = 0.35;

        resizeObserver = typeof ResizeObserver !== "undefined" ? new ResizeObserver(resize) : null;
        if (resizeObserver) resizeObserver.observe(container);
        window.addEventListener("resize", resize);
        resize();

        // Cloud layer: three-globe/globe.gl have no first-class "clouds" API,
        // so — same as the reference example — a second, larger, transparent
        // sphere is added straight to the scene and spun independently,
        // using the THREE captured by ensureGlobeLibrary above.
        new THREE.TextureLoader().load(VENDOR_BASE + "clouds.webp", (cloudsTexture) => {
          if (destroyed) return;
          cloudsMesh = new THREE.Mesh(
            new THREE.SphereGeometry(world.getGlobeRadius() * (1 + CLOUDS_ALTITUDE), 75, 75),
            new THREE.MeshPhongMaterial({ map: cloudsTexture, transparent: true })
          );
          world.scene().add(cloudsMesh);
          (function rotateClouds() {
            if (destroyed || !cloudsMesh) return;
            cloudsMesh.rotation.y += (CLOUDS_ROTATION_SPEED_DEG * Math.PI) / 180;
            requestAnimationFrame(rotateClouds);
          })();
        });

        connect();
      })
      .catch((err) => {
        console.warn("atomwall globe: failed to load renderer", err);
        if (!destroyed) container.textContent = "Live globe failed to load.";
      });

    return {
      destroy() {
        destroyed = true;
        clearInterval(pruneTimer);
        if (eventSource) eventSource.close();
        if (resizeObserver) resizeObserver.disconnect();
        window.removeEventListener("resize", resize);
        if (world) {
          try {
            world.renderer().forceContextLoss();
            world.renderer().dispose();
          } catch (err) {
            // best-effort GPU cleanup — falling through to the DOM clear
            // below still stops rendering either way
          }
        }
        container.innerHTML = "";
      },
      setServerLocation(loc) {
        serverLoc = loc || null;
      },
    };
  }

  window.AtomwallGlobe = { mount };

  // ---- public-embed auto-mount ----
  if (SELF_SCRIPT && SELF_SCRIPT.hasAttribute("data-atomwall-globe")) {
    const run = () => {
      const explicitBase = SELF_SCRIPT.getAttribute("data-endpoint-base");
      const base = explicitBase || new URL(".", SELF_SCRIPT.src).origin;

      let container = document.getElementById("atomwall-globe");
      if (!container) {
        container = document.createElement("div");
        container.id = "atomwall-globe";
        container.style.position = "fixed";
        container.style.right = "16px";
        container.style.bottom = "16px";
        container.style.width = "260px";
        container.style.height = "260px";
        container.style.borderRadius = "12px";
        container.style.overflow = "hidden";
        container.style.background = "rgba(10, 12, 18, 0.55)";
        container.style.backdropFilter = "blur(4px)";
        container.style.zIndex = "2147483000";
        container.style.pointerEvents = "auto";
        document.body.appendChild(container);
      }

      mount(container, {
        snapshotUrl: base + "/globe/snapshot",
        streamUrl: base + "/globe/stream",
      });
    };
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", run);
    } else {
      run();
    }
  }
})();
