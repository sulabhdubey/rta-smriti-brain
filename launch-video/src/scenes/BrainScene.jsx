import { Img, Easing, interpolate, staticFile, useCurrentFrame } from "remotion";
import { Brand, Eyebrow, PulseLine, Reveal, Scene, palette } from "../ui";

export const BrainScene = () => {
  const frame = useCurrentFrame();
  return <Scene><Brand /><PulseLine top={190} left={130} width={1500} delay={18} />
    <div style={{ position: "absolute", left: 100, top: 210, zIndex: 2, width: 760 }}>
      <Reveal><Eyebrow>One local continuity system</Eyebrow></Reveal>
      <Reveal from={14}><h1 style={{ margin: "18px 0 20px", fontSize: 88, lineHeight: 1 }}>Capture. Verify.<br />Continue.</h1></Reveal>
      <Reveal from={30}><p style={{ margin: 0, color: palette.muted, fontSize: 32, lineHeight: 1.45 }}>Repository evidence, checkpoints, bitemporal truth, capture, and governed context stay local and inspectable.</p></Reveal>
    </div>
    <Img src={staticFile("dashboard-v1.0.2.png")} style={{ position: "absolute", right: -90, bottom: -25, width: 1280, border: `1px solid ${palette.line}`, borderRadius: 10, boxShadow: "0 40px 100px #000", rotate: "-2deg", scale: interpolate(frame, [0, 45], [.92, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp", easing: Easing.bezier(.16,1,.3,1) }), opacity: interpolate(frame, [0, 20], [0, 1], { extrapolateRight: "clamp" }) }} />
  </Scene>;
};
