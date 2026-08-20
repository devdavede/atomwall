# Third-party licenses

atomwall vendors a small number of third-party JavaScript libraries directly into
`source/webui/vendor/` (see `CLAUDE.md`'s "Live Visitor Globe" section for why they're
vendored rather than loaded from a CDN). Their license terms require the copyright and
permission notice below to be included in copies of the software — reproduced here in full.

## globe.gl

`source/webui/vendor/globe.gl.min.js`

MIT License

Copyright (c) 2019 Vasco Asturiano

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Source: https://github.com/vasturiano/globe.gl

## three.js

`source/webui/vendor/three.min.js` (a dependency of globe.gl, loaded alongside it —
see `CLAUDE.md` for why it's captured into a closure-local variable instead of left global)

The MIT License

Copyright © 2010-2026 three.js authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Source: https://github.com/mrdoob/three.js

## GeoIP data (not bundled — operator-supplied)

atomwall's GeoIP feature (`geoip.mmdb_path`, see `CLAUDE.md`'s "Live Visitor Globe" section)
reads a `.mmdb` database that is *not* included in this repository — an operator downloads
one themselves and points `geoip.mmdb_path` at it. Both supported sources require
attribution from anything that uses their data, which is the operator's responsibility to
provide (e.g. on the site atomwall protects), same as the privacy-notice responsibility
called out in the README:

- **MaxMind GeoLite2** — per the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula),
  include: *"This product includes GeoLite2 data created by MaxMind, available from
  https://www.maxmind.com."*
- **DB-IP Lite** — licensed under
  [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); DB-IP's suggested attribution
  for web use is a visible link back to them, e.g.
  `<a href="https://db-ip.com">IP Geolocation by DB-IP</a>`.
