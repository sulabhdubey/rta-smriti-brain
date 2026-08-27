import { Img, Easing, interpolate, staticFile, useCurrentFrame } from "remotion";
import { Scene, palette } from "../ui";

export const FinaleScene = () => {
  const frame = useCurrentFrame();
  return <Scene>
    <Img src={staticFile("dashboard-v1.0.2.png")} style={{ position:"absolute",inset:0,width:"100%",height:"100%",objectFit:"cover",opacity:.34,scale:interpolate(frame,[0,300],[1.05,1],{extrapolateRight:"clamp"}) }} />
    <div style={{ position:"absolute",inset:0,background:"rgba(3,8,13,.54)" }} />
    <div style={{ position:"absolute",left:110,top:235,width:1120,opacity:interpolate(frame,[0,24,245,275],[0,1,1,0],{extrapolateLeft:"clamp",extrapolateRight:"clamp",easing:Easing.bezier(.16,1,.3,1)}),translate:`0 ${interpolate(frame,[0,24],[30,0],{extrapolateRight:"clamp"})}px` }}>
      <div style={{ color:palette.teal,fontSize:22,fontWeight:850,textTransform:"uppercase" }}>Rta-Smriti Brain · v1.0.2</div>
      <h1 style={{ margin:"20px 0 26px",fontSize:118,lineHeight:.96,letterSpacing:0 }}>Give every project<br />governed continuity.</h1>
      <p style={{ margin:0,color:palette.muted,fontSize:36,lineHeight:1.4 }}>Project Reality · Universal Capture · Governed Context</p>
      <div style={{ display:"inline-flex",marginTop:55,padding:"18px 24px",border:`1px solid ${palette.teal}`,borderRadius:7,background:"rgba(8,30,35,.82)",fontFamily:"ui-monospace, monospace",fontSize:24,color:palette.text }}>v1.0.2-alpha · Local-first · Open source · MIT</div>
    </div>
  </Scene>;
};
