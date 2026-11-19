// Browser entry: identical component tree to harness_render.cjs, bundled for
// a real browser. Config comes from ?db= & ?token= query params.
import React from "react";
import { createRoot } from "react-dom/client";
import { PlasmicQueryDataProvider } from "@plasmicapp/query";
import {
  CmsCredentialsProvider,
  CmsQueryRepeater,
  CmsRowField,
} from "@plasmicpkgs/plasmic-cms";

const q = new URLSearchParams(location.search);
const app = (
  <PlasmicQueryDataProvider>
    <CmsCredentialsProvider
      host="http://localhost:3004"
      databaseId={q.get("db")}
      databaseToken={q.get("token")}
    >
      <CmsQueryRepeater table="posts">
        <CmsRowField table="posts" field="body" />
      </CmsQueryRepeater>
    </CmsCredentialsProvider>
  </PlasmicQueryDataProvider>
);
createRoot(document.getElementById("root")).render(app);
