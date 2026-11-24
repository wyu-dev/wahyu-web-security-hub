import React from "react";

export function NoticeBanner({ htmlMessage }) {
  return (
    <div
      className="banner"
      dangerouslySetInnerHTML={{ __html: htmlMessage }}
    />
  );
}
