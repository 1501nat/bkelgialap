-- Add status column to enrollments table for approval workflow
ALTER TABLE public.enrollments 
ADD COLUMN status text NOT NULL DEFAULT 'pending';

-- Add constraint for valid status values
ALTER TABLE public.enrollments 
ADD CONSTRAINT enrollments_status_check 
CHECK (status IN ('pending', 'approved', 'rejected'));