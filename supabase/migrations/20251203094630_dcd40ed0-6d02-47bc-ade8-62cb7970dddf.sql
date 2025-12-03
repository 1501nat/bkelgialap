-- Add schedule column to courses table for storing timetable data
ALTER TABLE public.courses ADD COLUMN IF NOT EXISTS schedule JSONB DEFAULT '[]'::jsonb;