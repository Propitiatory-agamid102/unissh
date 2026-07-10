// Type augmentation: makes t() check key names against the RU catalog and
// autocomplete them. RU is the dev/source language; EN parity is asserted at
// dev-runtime in ./index.ts (plural suffixes differ per language, so a pure
// `typeof ru` parity on EN isn't practical).

import "i18next";
import type { ru } from "./locales/ru";

declare module "i18next" {
  interface CustomTypeOptions {
    defaultNS: "translation";
    resources: { translation: typeof ru };
  }
}
