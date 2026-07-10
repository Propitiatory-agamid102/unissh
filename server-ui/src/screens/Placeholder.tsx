import { useTranslation } from "react-i18next";
import { useUi } from "../store/ui";
import { EmptyState } from "../ui/primitives";
import { Screen } from "./Screen";
import { ZK_TAG } from "./meta";

export function Placeholder() {
  const { t } = useTranslation();
  const route = useUi((s) => s.route);
  return (
    <Screen
      title={t(`screen.${route}.title`)}
      sub={t(`screen.${route}.sub`)}
      zk={ZK_TAG.has(route)}
    >
      <EmptyState icon="box" title={t("screen.placeholder.title")} hint={t("screen.placeholder.hint")} />
    </Screen>
  );
}
