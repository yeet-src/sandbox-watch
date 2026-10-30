// Status rail: brand chip, what we're scoped to, and the live/paused state.
// The scope matters enough to sit in the chrome; "did the agent's sandbox
// hold" is only meaningful if you can see which agent.
import { Box, Text } from "yeet:tui";
import { C_BRAND, C_DIM, C_FAINT, C_RAIL, C_TEXT, C_WARN } from "@/lib/format.js";

const sep = () => <Text fg={C_FAINT}>{"  ▏  "}</Text>;

export default ({ scope, status, paused }) => (
  <Box height="1" direction="row" bg={C_RAIL}>
    <Text break="none">
      {() => [
        <Text bold fg={C_BRAND}>{" ● sandbox-watch "}</Text>, sep(),
        <Text fg={C_DIM}>{"scope "}</Text>, <Text bold fg={C_TEXT}>{scope.get()}</Text>, sep(),
        paused.get()
          ? <Text bold fg={C_WARN}>{"‖ paused"}</Text>
          : <Text fg={C_DIM}>{status.get()}</Text>,
      ]}
    </Text>
  </Box>
);
