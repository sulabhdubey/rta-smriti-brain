import { Composition, Folder } from "remotion";
import { LaunchVideo } from "./LaunchVideo";
import { ProblemScene } from "./scenes/ProblemScene";
import { BrainScene } from "./scenes/BrainScene";
import { CaptureScene } from "./scenes/CaptureScene";
import { ProjectRealityScene } from "./scenes/ProjectRealityScene";
import { EvidenceScene } from "./scenes/EvidenceScene";
import { AgentScene } from "./scenes/AgentScene";
import { ContextScene } from "./scenes/ContextScene";
import { FinaleScene } from "./scenes/FinaleScene";

const video = { fps: 30, width: 1920, height: 1080 };

export const VideoRoot = () => (
  <>
    <Folder name="Launch-scenes">
      <Composition id="ProblemScene" component={ProblemScene} durationInFrames={200} {...video} />
      <Composition id="BrainScene" component={BrainScene} durationInFrames={230} {...video} />
      <Composition id="CaptureScene" component={CaptureScene} durationInFrames={220} {...video} />
      <Composition id="ProjectRealityScene" component={ProjectRealityScene} durationInFrames={300} {...video} />
      <Composition id="EvidenceScene" component={EvidenceScene} durationInFrames={220} {...video} />
      <Composition id="AgentScene" component={AgentScene} durationInFrames={190} {...video} />
      <Composition id="ContextScene" component={ContextScene} durationInFrames={300} {...video} />
      <Composition id="FinaleScene" component={FinaleScene} durationInFrames={280} {...video} />
    </Folder>
    <Composition id="RtaSmritiLaunch" component={LaunchVideo} durationInFrames={1800} {...video} />
  </>
);
