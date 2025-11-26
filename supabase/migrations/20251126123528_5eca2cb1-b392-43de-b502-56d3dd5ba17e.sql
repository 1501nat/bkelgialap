-- Create table to store user passwords (for admin viewing only)
-- WARNING: This is a security risk in production environments
CREATE TABLE public.user_passwords (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  password text NOT NULL,
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  updated_at timestamp with time zone NOT NULL DEFAULT now(),
  created_by uuid REFERENCES auth.users(id),
  UNIQUE(user_id)
);

-- Enable RLS
ALTER TABLE public.user_passwords ENABLE ROW LEVEL SECURITY;

-- Only admins can view passwords
CREATE POLICY "Admins can view all passwords"
ON public.user_passwords
FOR SELECT
TO authenticated
USING (has_role(auth.uid(), 'admin'::app_role));

-- Only admins can insert passwords
CREATE POLICY "Admins can insert passwords"
ON public.user_passwords
FOR INSERT
TO authenticated
WITH CHECK (has_role(auth.uid(), 'admin'::app_role));

-- Only admins can update passwords
CREATE POLICY "Admins can update passwords"
ON public.user_passwords
FOR UPDATE
TO authenticated
USING (has_role(auth.uid(), 'admin'::app_role));

-- Only admins can delete passwords
CREATE POLICY "Admins can delete passwords"
ON public.user_passwords
FOR DELETE
TO authenticated
USING (has_role(auth.uid(), 'admin'::app_role));

-- Add trigger to update updated_at
CREATE TRIGGER update_user_passwords_updated_at
BEFORE UPDATE ON public.user_passwords
FOR EACH ROW
EXECUTE FUNCTION public.handle_updated_at();