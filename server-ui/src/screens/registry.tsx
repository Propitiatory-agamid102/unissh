import type { ComponentType } from "react";
import { useUi, type Route } from "../store/ui";
import { Accounts } from "./Accounts";
import { Audit } from "./Audit";
import { Config } from "./Config";
import { Devices } from "./Devices";
import { Enroll } from "./Enroll";
import { Grants } from "./Grants";
import { Health } from "./Health";
import { Invites } from "./Invites";
import { Maintenance } from "./Maintenance";
import { Metrics } from "./Metrics";
import { Objects } from "./Objects";
import { Overview } from "./Overview";
import { Relay } from "./Relay";
import { Sessions } from "./Sessions";
import { Tenants } from "./Tenants";
import { Vaults } from "./Vaults";

const SCREENS: Record<Route, ComponentType> = {
  overview: Overview,
  health: Health,
  metrics: Metrics,
  config: Config,
  maint: Maintenance,
  tenants: Tenants,
  accounts: Accounts,
  devices: Devices,
  sessions: Sessions,
  invites: Invites,
  vaults: Vaults,
  grants: Grants,
  enroll: Enroll,
  relay: Relay,
  objects: Objects,
  audit: Audit,
};

export function ScreenRouter() {
  const route = useUi((s) => s.route);
  const C = SCREENS[route];
  return <C />;
}
