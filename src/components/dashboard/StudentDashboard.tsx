import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { BookOpen, FileText, ChevronLeft, ChevronRight } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { format, startOfMonth, endOfMonth, eachDayOfInterval, isSameMonth, isSameDay, addMonths, subMonths, getDay } from 'date-fns';
import { vi } from 'date-fns/locale';
import { cn } from '@/lib/utils';
interface Course {
  id: string;
  name: string;
  code: string;
  schedule: { day: string; period: string }[];
}

interface Assignment {
  id: string;
  title: string;
  due_date: string | null;
  course_name: string;
}

interface CalendarEvent {
  type: 'course' | 'assignment';
  title: string;
  details: string;
  color: string;
}

const DAY_MAP: { [key: string]: number } = {
  'Chủ nhật': 0,
  'Thứ 2': 1,
  'Thứ 3': 2,
  'Thứ 4': 3,
  'Thứ 5': 4,
  'Thứ 6': 5,
  'Thứ 7': 6,
};

export const StudentDashboard = () => {
  const { user } = useAuth();
  const [courses, setCourses] = useState<Course[]>([]);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentMonth, setCurrentMonth] = useState(new Date());

  useEffect(() => {
    fetchData();
  }, [user]);

  const fetchData = async () => {
    if (!user) return;

    try {
      // Get approved enrollments
      const { data: enrollments } = await supabase
        .from('enrollments')
        .select('course_id')
        .eq('student_id', user.id)
        .eq('status', 'approved');

      const courseIds = enrollments?.map(e => e.course_id) || [];

      if (courseIds.length > 0) {
        // Fetch courses
        const { data: coursesData } = await supabase
          .from('courses')
          .select('id, name, code, schedule')
          .in('id', courseIds);

        const parsedCourses: Course[] = (coursesData || []).map(course => ({
          id: course.id,
          name: course.name,
          code: course.code,
          schedule: Array.isArray(course.schedule) 
            ? (course.schedule as { day: string; period: string }[]) 
            : []
        }));
        setCourses(parsedCourses);

        // Fetch assignments
        const { data: assignmentsData } = await supabase
          .from('assignments')
          .select('id, title, due_date, course_id')
          .in('course_id', courseIds)
          .order('due_date', { ascending: true });

        const assignmentsWithCourse = (assignmentsData || []).map(a => {
          const course = parsedCourses.find(c => c.id === a.course_id);
          return {
            ...a,
            course_name: course?.name || ''
          };
        });
        setAssignments(assignmentsWithCourse);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Get events for a specific day
  const getEventsForDay = (date: Date): CalendarEvent[] => {
    const events: CalendarEvent[] = [];
    const dayOfWeek = getDay(date);

    // Check course schedules
    courses.forEach(course => {
      course.schedule.forEach(schedule => {
        const scheduleDayNumber = DAY_MAP[schedule.day];
        if (scheduleDayNumber === dayOfWeek) {
          events.push({
            type: 'course',
            title: course.code,
            details: `Tiết ${schedule.period}`,
            color: 'bg-primary/20 text-primary border-primary/30'
          });
        }
      });
    });

    // Check assignment due dates
    assignments.forEach(assignment => {
      if (assignment.due_date && isSameDay(new Date(assignment.due_date), date)) {
        events.push({
          type: 'assignment',
          title: assignment.title,
          details: assignment.course_name,
          color: 'bg-destructive/20 text-destructive border-destructive/30'
        });
      }
    });

    return events;
  };

  const monthStart = startOfMonth(currentMonth);
  const monthEnd = endOfMonth(currentMonth);
  const daysInMonth = eachDayOfInterval({ start: monthStart, end: monthEnd });

  // Get starting day offset
  const startDayOffset = getDay(monthStart);

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
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
        <h1 className="text-3xl font-bold text-foreground mb-2">Bảng điều khiển Sinh viên</h1>
        <p className="text-muted-foreground">Theo dõi tiến độ học tập của bạn</p>
      </motion.div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Link to="/courses">
            <Card className="shadow-card hover:shadow-hover transition-all cursor-pointer">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Khóa học đã đăng ký
                </CardTitle>
                <BookOpen className="h-5 w-5 text-primary" />
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-foreground">{courses.length}</div>
                <p className="text-sm text-muted-foreground mt-1">
                  Khóa học đã được duyệt
                </p>
              </CardContent>
            </Card>
          </Link>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Link to="/assignments">
            <Card className="shadow-card hover:shadow-hover transition-all cursor-pointer">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium text-muted-foreground">
                  Bài tập cần thực hiện
                </CardTitle>
                <FileText className="h-5 w-5 text-primary" />
              </CardHeader>
              <CardContent>
                <div className="text-3xl font-bold text-foreground">{assignments.length}</div>
                <p className="text-sm text-muted-foreground mt-1">
                  Bài tập từ các khóa học
                </p>
              </CardContent>
            </Card>
          </Link>
        </motion.div>
      </div>

      {/* Calendar */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card className="shadow-card">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Lịch học tập</CardTitle>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setCurrentMonth(subMonths(currentMonth, 1))}
                >
                  <ChevronLeft className="h-4 w-4" />
                </Button>
                <span className="text-lg font-medium min-w-[150px] text-center">
                  {format(currentMonth, 'MMMM yyyy', { locale: vi })}
                </span>
                <Button
                  variant="outline"
                  size="icon"
                  onClick={() => setCurrentMonth(addMonths(currentMonth, 1))}
                >
                  <ChevronRight className="h-4 w-4" />
                </Button>
              </div>
            </div>
            <div className="flex items-center gap-4 mt-4 text-sm">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-primary/20 border border-primary/30"></div>
                <span className="text-muted-foreground">Lịch học</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-destructive/20 border border-destructive/30"></div>
                <span className="text-muted-foreground">Hạn nộp bài</span>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {/* Day headers */}
            <div className="grid grid-cols-7 gap-1 mb-2">
              {['CN', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7'].map(day => (
                <div
                  key={day}
                  className="text-center text-sm font-medium text-muted-foreground py-2"
                >
                  {day}
                </div>
              ))}
            </div>

            {/* Calendar grid */}
            <div className="grid grid-cols-7 gap-1">
              {/* Empty cells for offset */}
              {Array.from({ length: startDayOffset }).map((_, i) => (
                <div key={`empty-${i}`} className="min-h-[100px] p-1"></div>
              ))}

              {/* Days */}
              {daysInMonth.map(day => {
                const events = getEventsForDay(day);
                const isToday = isSameDay(day, new Date());

                return (
                  <div
                    key={day.toISOString()}
                    className={cn(
                      "min-h-[100px] p-1 border rounded-lg transition-colors",
                      isToday ? "border-primary bg-primary/5" : "border-border",
                      !isSameMonth(day, currentMonth) && "opacity-50"
                    )}
                  >
                    <div className={cn(
                      "text-sm font-medium mb-1 text-center",
                      isToday ? "text-primary" : "text-foreground"
                    )}>
                      {format(day, 'd')}
                    </div>
                    <div className="space-y-1">
                      {events.slice(0, 3).map((event, idx) => (
                        <div
                          key={idx}
                          className={cn(
                            "text-xs p-1 rounded border truncate",
                            event.color
                          )}
                          title={`${event.title} - ${event.details}`}
                        >
                          {event.title}
                        </div>
                      ))}
                      {events.length > 3 && (
                        <div className="text-xs text-muted-foreground text-center">
                          +{events.length - 3} khác
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
};
