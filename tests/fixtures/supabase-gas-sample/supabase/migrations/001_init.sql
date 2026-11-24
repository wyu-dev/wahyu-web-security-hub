CREATE TABLE public.complaints (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  details text NOT NULL
);

CREATE POLICY "open_write" ON public.complaints
  FOR ALL USING (true) WITH CHECK (true);
