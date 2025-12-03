import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { FileText, PlusCircle, Clock, CheckCircle, Calendar, Edit, Trash2, BookOpen, ExternalLink } from 'lucide-react';
import { format } from 'date-fns';
import SubmissionForm from '@/components/assignments/SubmissionForm';
import SubmissionsList from '@/components/assignments/SubmissionsList';

interface Assignment {
  id: string;
  title: string;
  description: string | null;
  course_id: string;
  due_date: string | null;
  max_score: number;
  created_at: string;
  link_url: string | null;
  course_name?: string;
  course_code?: string;
  submission_status?: 'submitted' | 'graded' | 'pending';
  score?: number;
  submission?: {
    id: string;
    file_url: string | null;
    content: string | null;
  } | null;
}

interface GroupedAssignments {
  [courseId: string]: {
    course_name: string;
    course_code: string;
    assignments: Assignment[];
  };
}

const Assignments = () => {
  const { role, user } = useAuth();
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [courses, setCourses] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [open, setOpen] = useState(false);
  const [editingAssignment, setEditingAssignment] = useState<Assignment | null>(null);
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    course_id: '',
    due_date: '',
    max_score: 100,
    link_url: ''
  });

  useEffect(() => {
    fetchData();
  }, [role, user]);

  const fetchData = async () => {
    try {
      let coursesQuery = supabase.from('courses').select('*');
      let courseIds: string[] = [];
      
      if (role === 'lecturer') {
        coursesQuery = coursesQuery.eq('lecturer_id', user?.id);
        const { data: coursesData } = await coursesQuery;
        setCourses(coursesData || []);
        courseIds = coursesData?.map(c => c.id) || [];
      } else if (role === 'student') {
        // Only get enrollments with approved status
        const { data: enrollments } = await supabase
          .from('enrollments')
          .select('course_id')
          .eq('student_id', user?.id)
          .eq('status', 'approved');
        
        courseIds = enrollments?.map(e => e.course_id) || [];
        
        if (courseIds.length > 0) {
          const { data: coursesData } = await supabase
            .from('courses')
            .select('*')
            .in('id', courseIds);
          setCourses(coursesData || []);
        } else {
          setCourses([]);
        }
      } else if (role === 'admin') {
        const { data: coursesData } = await coursesQuery;
        setCourses(coursesData || []);
        courseIds = coursesData?.map(c => c.id) || [];
      }

      // Fetch assignments only if there are courses
      if (courseIds.length === 0) {
        setAssignments([]);
        setLoading(false);
        return;
      }

      const { data: assignmentsData, error } = await supabase
        .from('assignments')
        .select('*')
        .in('course_id', courseIds)
        .order('due_date', { ascending: true });

      if (error) throw error;

      // Get courses for reference
      const coursesForRef = courses.length > 0 ? courses : (await supabase.from('courses').select('*').in('id', courseIds)).data || [];

      // Add course names and submission status
      const assignmentsWithDetails = await Promise.all(
        (assignmentsData || []).map(async (assignment) => {
          const course = coursesForRef.find(c => c.id === assignment.course_id);
          
          let submissionStatus = 'pending';
          let score = undefined;
          
          let submissionData = null;
          
          if (role === 'student') {
            const { data: submission } = await supabase
              .from('submissions')
              .select('id, score, graded_at, file_url, content')
              .eq('assignment_id', assignment.id)
              .eq('student_id', user?.id)
              .maybeSingle();
            
            if (submission) {
              submissionStatus = submission.graded_at ? 'graded' : 'submitted';
              score = submission.score;
              submissionData = {
                id: submission.id,
                file_url: submission.file_url,
                content: submission.content
              };
            }
          }
          
          return {
            ...assignment,
            course_name: course?.name,
            course_code: course?.code,
            submission_status: submissionStatus as any,
            score,
            submission: submissionData
          };
        })
      );

      setAssignments(assignmentsWithDetails);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách bài tập');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingAssignment) {
        const { error } = await supabase
          .from('assignments')
          .update(formData)
          .eq('id', editingAssignment.id);

        if (error) throw error;
        toast.success('Cập nhật bài tập thành công');
      } else {
        const { error } = await supabase
          .from('assignments')
          .insert([formData]);

        if (error) throw error;
        toast.success('Tạo bài tập thành công');
      }

      setOpen(false);
      setEditingAssignment(null);
      resetForm();
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Bạn có chắc chắn muốn xóa bài tập này?')) return;
    
    try {
      const { error } = await supabase
        .from('assignments')
        .delete()
        .eq('id', id);

      if (error) throw error;
      toast.success('Xóa bài tập thành công');
      fetchData();
    } catch (error: any) {
      toast.error(error.message || 'Có lỗi xảy ra');
    }
  };

  const resetForm = () => {
    setFormData({
      title: '',
      description: '',
      course_id: '',
      due_date: '',
      max_score: 100,
      link_url: ''
    });
  };

  const openEditDialog = (assignment: Assignment) => {
    setEditingAssignment(assignment);
    setFormData({
      title: assignment.title,
      description: assignment.description || '',
      course_id: assignment.course_id,
      due_date: assignment.due_date ? format(new Date(assignment.due_date), 'yyyy-MM-dd') : '',
      max_score: assignment.max_score,
      link_url: assignment.link_url || ''
    });
    setOpen(true);
  };

  const getStatusBadge = (assignment: Assignment) => {
    if (role !== 'student') return null;
    
    switch (assignment.submission_status) {
      case 'graded':
        return (
          <div className="flex items-center gap-2 text-success">
            <CheckCircle className="h-4 w-4" />
            <span className="text-sm font-medium">Đã chấm: {assignment.score}/{assignment.max_score}</span>
          </div>
        );
      case 'submitted':
        return (
          <div className="flex items-center gap-2 text-warning">
            <Clock className="h-4 w-4" />
            <span className="text-sm font-medium">Đã nộp</span>
          </div>
        );
      default:
        return (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Clock className="h-4 w-4" />
            <span className="text-sm font-medium">Chưa nộp</span>
          </div>
        );
    }
  };

  // Group assignments by course
  const groupedAssignments: GroupedAssignments = assignments.reduce((acc, assignment) => {
    const courseId = assignment.course_id;
    if (!acc[courseId]) {
      acc[courseId] = {
        course_name: assignment.course_name || 'Không xác định',
        course_code: assignment.course_code || '',
        assignments: []
      };
    }
    acc[courseId].assignments.push(assignment);
    return acc;
  }, {} as GroupedAssignments);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="container py-8 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="mb-8"
      >
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold text-foreground mb-2">Bài tập</h1>
            <p className="text-muted-foreground">
              {role === 'student' 
                ? 'Xem và nộp bài tập của bạn' 
                : 'Quản lý bài tập cho các khóa học'}
            </p>
          </div>
          {(role === 'admin' || role === 'lecturer') && (
            <Dialog open={open} onOpenChange={setOpen}>
              <DialogTrigger asChild>
                <Button onClick={() => { setEditingAssignment(null); resetForm(); }}>
                  <PlusCircle className="h-4 w-4 mr-2" />
                  Tạo bài tập
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl">
                <DialogHeader>
                  <DialogTitle>
                    {editingAssignment ? 'Chỉnh sửa bài tập' : 'Tạo bài tập mới'}
                  </DialogTitle>
                </DialogHeader>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <Label htmlFor="title">Tiêu đề *</Label>
                    <Input
                      id="title"
                      value={formData.title}
                      onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                      required
                    />
                  </div>
                  <div>
                    <Label htmlFor="course">Khóa học *</Label>
                    <Select
                      value={formData.course_id}
                      onValueChange={(value) => setFormData({ ...formData, course_id: value })}
                      required
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Chọn khóa học" />
                      </SelectTrigger>
                      <SelectContent>
                        {courses.map((course) => (
                          <SelectItem key={course.id} value={course.id}>
                            {course.code} - {course.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label htmlFor="description">Mô tả</Label>
                    <Textarea
                      id="description"
                      value={formData.description}
                      onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                      rows={4}
                    />
                  </div>
                  <div>
                    <Label htmlFor="link_url">Link bài tập</Label>
                    <Input
                      id="link_url"
                      type="url"
                      placeholder="https://..."
                      value={formData.link_url}
                      onChange={(e) => setFormData({ ...formData, link_url: e.target.value })}
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <Label htmlFor="due_date">Hạn nộp</Label>
                      <Input
                        id="due_date"
                        type="date"
                        value={formData.due_date}
                        onChange={(e) => setFormData({ ...formData, due_date: e.target.value })}
                      />
                    </div>
                    <div>
                      <Label htmlFor="max_score">Điểm tối đa</Label>
                      <Input
                        id="max_score"
                        type="number"
                        value={formData.max_score}
                        onChange={(e) => setFormData({ ...formData, max_score: parseInt(e.target.value) })}
                        min="1"
                        required
                      />
                    </div>
                  </div>
                  <div className="flex justify-end gap-2">
                    <Button type="button" variant="outline" onClick={() => setOpen(false)}>
                      Hủy
                    </Button>
                    <Button type="submit">
                      {editingAssignment ? 'Cập nhật' : 'Tạo'}
                    </Button>
                  </div>
                </form>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </motion.div>

      {Object.keys(groupedAssignments).length === 0 ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <p className="text-muted-foreground">
              {role === 'student' 
                ? 'Chưa có bài tập nào từ các khóa học đã được duyệt' 
                : 'Chưa có bài tập nào'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="space-y-8">
          {Object.entries(groupedAssignments).map(([courseId, group], groupIndex) => (
            <motion.div
              key={courseId}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: groupIndex * 0.1 }}
            >
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-lg bg-primary/10">
                  <BookOpen className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-foreground">
                    {group.course_code} - {group.course_name}
                  </h2>
                  <p className="text-sm text-muted-foreground">
                    {group.assignments.length} bài tập
                  </p>
                </div>
              </div>

              <div className="grid gap-4 pl-4 border-l-2 border-primary/20">
                {group.assignments.map((assignment, index) => (
                  <motion.div
                    key={assignment.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05 }}
                  >
                    <Card className="shadow-card hover:shadow-hover transition-shadow">
                      <CardHeader>
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <CardTitle className="text-lg mb-2">{assignment.title}</CardTitle>
                            <div className="flex items-center gap-4 text-sm text-muted-foreground flex-wrap">
                              {assignment.due_date && (
                                <div className="flex items-center gap-1">
                                  <Calendar className="h-4 w-4" />
                                  <span>Hạn: {format(new Date(assignment.due_date), 'dd/MM/yyyy')}</span>
                                </div>
                              )}
                              <span>Điểm: {assignment.max_score}</span>
                              {assignment.link_url && (
                                <a 
                                  href={assignment.link_url} 
                                  target="_blank" 
                                  rel="noopener noreferrer"
                                  className="flex items-center gap-1 text-primary hover:underline"
                                >
                                  <ExternalLink className="h-4 w-4" />
                                  <span>Link bài tập</span>
                                </a>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {getStatusBadge(assignment)}
                            {role === 'student' && (
                              <SubmissionForm
                                assignmentId={assignment.id}
                                userId={user?.id || ''}
                                existingSubmission={assignment.submission}
                                onSubmitSuccess={fetchData}
                              />
                            )}
                            {(role === 'admin' || role === 'lecturer') && (
                              <>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  onClick={() => openEditDialog(assignment)}
                                >
                                  <Edit className="h-4 w-4" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  onClick={() => handleDelete(assignment.id)}
                                >
                                  <Trash2 className="h-4 w-4 text-destructive" />
                                </Button>
                              </>
                            )}
                          </div>
                        </div>
                      </CardHeader>
                      <CardContent className={assignment.description ? '' : 'pt-0'}>
                        {assignment.description && (
                          <p className="text-muted-foreground whitespace-pre-wrap mb-4">
                            {assignment.description}
                          </p>
                        )}
                        {(role === 'admin' || role === 'lecturer') && (
                          <SubmissionsList assignmentId={assignment.id} />
                        )}
                      </CardContent>
                    </Card>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Assignments;
