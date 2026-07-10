import { OpsLogin } from "./access/OpsLogin";
import { Shell } from "./shell/Shell";
import { useSession } from "./store/session";
import { ThemeProvider } from "./theme/ThemeProvider";

function Root() {
  const opsToken = useSession((s) => s.opsToken);
  return opsToken ? <Shell /> : <OpsLogin />;
}

export function App() {
  return (
    <ThemeProvider>
      <Root />
    </ThemeProvider>
  );
}
