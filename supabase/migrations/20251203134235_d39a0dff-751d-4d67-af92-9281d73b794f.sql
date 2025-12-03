-- Drop existing check constraint and add new one with withdrawal_pending status
ALTER TABLE public.enrollments DROP CONSTRAINT IF EXISTS enrollments_status_check;

ALTER TABLE public.enrollments ADD CONSTRAINT enrollments_status_check 
CHECK (status IN ('pending', 'approved', 'rejected', 'withdrawal_pending'));