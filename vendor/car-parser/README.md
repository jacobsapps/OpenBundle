# CarParser browser dependency

OpenBundle vendors the generated browser module from
[`skytoup/car-parser`](https://github.com/skytoup/car-parser) at commit
`dee176b984598efbdf02ed2834aeb7cd01386046`.

The upstream project is MIT licensed; its license is included beside this
file. `openbundle.patch` adds read-only analysis data to the WASM response:

- serialized CoreUI rendition and payload sizes,
- whether the resolved rendition declares itself opaque, and
- a complete compact inventory of rendition trait keys used for device
  thinning.

These fields let the browser preserve CoreUI overhead in conversion estimates,
avoid proposing JPEG for an image that requires alpha, and estimate the catalog
bytes delivered to a current iPhone. The patch does not alter the CoreUI parser
or decoder.

Rebuild the checked-in module with:

```bash
./scripts/build_car_wasm.sh
```

The generated `car_wasm.js` and `car_wasm_bg.wasm` live under
`web/vendor/car-parser` so the deployed analyzer has no runtime dependency on
GitHub or a package registry.
