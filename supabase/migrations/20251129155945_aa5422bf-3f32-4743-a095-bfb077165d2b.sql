-- Add status column to courses for approval workflow
ALTER TABLE public.courses ADD COLUMN status text NOT NULL DEFAULT 'pending';
ALTER TABLE public.courses ADD CONSTRAINT courses_status_check 
  CHECK (status IN ('pending', 'approved', 'rejected'));

-- Create course_classes table (lớp theo môn)
CREATE TABLE public.course_classes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id uuid REFERENCES public.courses(id) ON DELETE CASCADE NOT NULL,
  class_code text NOT NULL,
  class_name text NOT NULL,
  max_students integer DEFAULT 50,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  UNIQUE(course_id, class_code)
);

-- Enable RLS on course_classes
ALTER TABLE public.course_classes ENABLE ROW LEVEL SECURITY;

-- RLS Policies for course_classes
CREATE POLICY "Everyone can view approved course classes"
  ON public.course_classes FOR SELECT
  USING (EXISTS (
    SELECT 1 FROM public.courses 
    WHERE courses.id = course_classes.course_id 
    AND courses.status = 'approved'
  ));

CREATE POLICY "Lecturers can manage classes for their courses"
  ON public.course_classes FOR ALL
  USING (EXISTS (
    SELECT 1 FROM public.courses 
    WHERE courses.id = course_classes.course_id 
    AND courses.lecturer_id = auth.uid()
  ));

CREATE POLICY "Admins can manage all classes"
  ON public.course_classes FOR ALL
  USING (has_role(auth.uid(), 'admin'));

-- Update enrollments to link to course_classes instead of courses directly
ALTER TABLE public.enrollments ADD COLUMN class_id uuid REFERENCES public.course_classes(id) ON DELETE CASCADE;

-- Create course_materials table for documents, videos, etc.
CREATE TABLE public.course_materials (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  course_id uuid REFERENCES public.courses(id) ON DELETE CASCADE NOT NULL,
  class_id uuid REFERENCES public.course_classes(id) ON DELETE CASCADE,
  title text NOT NULL,
  description text,
  material_type text NOT NULL,
  link_url text NOT NULL,
  created_by uuid NOT NULL,
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now(),
  CONSTRAINT material_type_check CHECK (material_type IN ('document', 'video', 'link', 'other'))
);

-- Enable RLS on course_materials
ALTER TABLE public.course_materials ENABLE ROW LEVEL SECURITY;

-- RLS Policies for course_materials
CREATE POLICY "Students can view materials for enrolled classes"
  ON public.course_materials FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM public.enrollments e
      WHERE (e.class_id = course_materials.class_id OR 
             (course_materials.class_id IS NULL AND e.course_id = course_materials.course_id))
      AND e.student_id = auth.uid()
    )
  );

CREATE POLICY "Lecturers can manage materials for their courses"
  ON public.course_materials FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM public.courses c
      WHERE c.id = course_materials.course_id 
      AND c.lecturer_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage all materials"
  ON public.course_materials FOR ALL
  USING (has_role(auth.uid(), 'admin'));

-- Add triggers for updated_at
CREATE TRIGGER update_course_classes_updated_at
  BEFORE UPDATE ON public.course_classes
  FOR EACH ROW EXECUTE FUNCTION handle_updated_at();

CREATE TRIGGER update_course_materials_updated_at
  BEFORE UPDATE ON public.course_materials
  FOR EACH ROW EXECUTE FUNCTION handle_updated_at();

-- Update courses RLS to only show approved courses to students
DROP POLICY IF EXISTS "Everyone can view courses" ON public.courses;

CREATE POLICY "Students can view approved courses"
  ON public.courses FOR SELECT
  USING (status = 'approved');

CREATE POLICY "Lecturers can view own courses"
  ON public.courses FOR SELECT
  USING (lecturer_id = auth.uid());

CREATE POLICY "Admins can view all courses"
  ON public.courses FOR SELECT
  USING (has_role(auth.uid(), 'admin'));