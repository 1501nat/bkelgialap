import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import { Users as UsersIcon, Search, Trash2, UserCog } from 'lucide-react';
import { Link } from 'react-router-dom';

interface UserData {
  id: string;
  email: string;
  full_name: string;
  created_at: string;
  role?: string;
}

const Users = () => {
  const [users, setUsers] = useState<UserData[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      const { data: profiles, error: profilesError } = await supabase
        .from('profiles')
        .select('*')
        .order('created_at', { ascending: false });

      if (profilesError) throw profilesError;

      const usersWithRoles = await Promise.all(
        (profiles || []).map(async (profile) => {
          const { data: roleData } = await supabase
            .from('user_roles')
            .select('role')
            .eq('user_id', profile.id)
            .single();

          return {
            ...profile,
            role: roleData?.role || 'student'
          };
        })
      );

      setUsers(usersWithRoles);
    } catch (error: any) {
      toast.error('Lỗi khi tải danh sách người dùng');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (userId: string, userEmail: string) => {
    if (!confirm(`Bạn có chắc muốn xóa người dùng ${userEmail}?`)) return;

    try {
      const { data, error } = await supabase.functions.invoke('admin-delete-user', {
        body: { user_id: userId }
      });

      if (error || data?.error) {
        throw new Error(error?.message || data?.error || 'Không thể xóa người dùng');
      }

      toast.success(`Đã xóa ${userEmail}`);
      setUsers((prev) => prev.filter((u) => u.id !== userId));
    } catch (err: any) {
      console.error(err);
      toast.error(err.message || 'Lỗi khi xóa người dùng');
    }
  };

  const filteredUsers = users.filter(user =>
    user.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const usersByRole = {
    admin: filteredUsers.filter((u) => u.role === 'admin'),
    lecturer: filteredUsers.filter((u) => u.role === 'lecturer'),
    student: filteredUsers.filter((u) => u.role === 'student'),
  };

  const getRoleBadgeVariant = (role: string) => {
    switch (role) {
      case 'admin':
        return 'destructive';
      case 'lecturer':
        return 'default';
      case 'student':
        return 'secondary';
      default:
        return 'outline';
    }
  };

  const getRoleLabel = (role: string) => {
    switch (role) {
      case 'admin':
        return 'Quản trị viên';
      case 'lecturer':
        return 'Giảng viên';
      case 'student':
        return 'Sinh viên';
      default:
        return role;
    }
  };

  const renderRoleSection = (roleKey: 'admin' | 'lecturer' | 'student', title: string) => {
    const list = usersByRole[roleKey];
    if (list.length === 0) return null;

    return (
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-foreground">
            {title} ({list.length})
          </h3>
        </div>
        {list.map((user, index) => (
          <motion.div
            key={user.id}
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: index * 0.05 }}
            className="flex items-center justify-between p-4 rounded-lg bg-accent/50 hover:bg-accent transition-colors"
          >
            <div className="flex items-center gap-4 flex-1">
              <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center">
                <UsersIcon className="h-6 w-6 text-primary" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <h3 className="font-medium text-foreground">{user.full_name}</h3>
                  <Badge variant={getRoleBadgeVariant(user.role || 'student')}>
                    {getRoleLabel(user.role || 'student')}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">{user.email}</p>
                <p className="text-xs text-muted-foreground">
                  Tham gia: {new Date(user.created_at).toLocaleDateString('vi-VN')}
                </p>
              </div>
            </div>
            <div className="flex gap-2">
              <Button
                size="icon"
                variant="ghost"
                onClick={() => handleDelete(user.id, user.email)}
                disabled={user.role === 'admin'}
              >
                <Trash2 className="h-4 w-4 text-destructive" />
              </Button>
            </div>
          </motion.div>
        ))}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="container py-8 px-4">
        <div className="flex items-center justify-center h-64">
          <p className="text-muted-foreground">Đang tải...</p>
        </div>
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
        <div className="flex justify-between items-center mb-6">
          <div>
            <h1 className="text-3xl font-bold text-foreground mb-2">Người dùng</h1>
            <p className="text-muted-foreground">Quản lý người dùng</p>
          </div>
          <Link to="/admin">
            <Button>
              <UserCog className="mr-2 h-4 w-4" />
              Tạo người dùng mới
            </Button>
          </Link>
        </div>

        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            type="text"
            placeholder="Tìm kiếm theo tên hoặc email..."
            className="pl-10"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="shadow-card">
          <CardHeader>
            <CardTitle>Danh sách Người dùng ({filteredUsers.length})</CardTitle>
          </CardHeader>
          <CardContent className="space-y-8">
            {renderRoleSection('admin', 'Quản trị viên')}
            {renderRoleSection('lecturer', 'Giảng viên')}
            {renderRoleSection('student', 'Sinh viên')}

            {filteredUsers.length === 0 && (
              <div className="text-center py-12">
                <UsersIcon className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">Không tìm thấy người dùng</p>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
};

export default Users;
