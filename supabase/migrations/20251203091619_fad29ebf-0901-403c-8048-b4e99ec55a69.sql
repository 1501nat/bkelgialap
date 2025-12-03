-- Add gender and phone columns to profiles
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS gender text;
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS phone text;

-- Add status column to announcements for approval workflow
ALTER TABLE public.announcements ADD COLUMN IF NOT EXISTS status text DEFAULT 'approved';

-- Update existing global announcements to approved
UPDATE public.announcements SET status = 'approved' WHERE status IS NULL;