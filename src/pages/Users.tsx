import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { supabase } from '@/integrations/supabase/client';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import { Users as UsersIcon, Search, Trash2, UserCog, Key, Eye, EyeOff } from 'lucide-react';
import { Link } from 'react-router-dom';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Label } from '@/components/ui/label';

interface UserData {
  id: string;
  email: string;
  full_name: string;
  created_at: string;
  role?: string;
  password?: string;
}

const Users = () => {
  const [users, setUsers] = useState<UserData[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [resetDialogOpen, setResetDialogOpen] = useState(false);
  const [selectedUser, setSelectedUser] = useState<UserData | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [resetting, setResetting] = useState(false);
  const [showPassword, setShowPassword] = useState<{[key: string]: boolean}>({});

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

      // Fetch roles and passwords for each user
      const usersWithRoles = await Promise.all(
        (profiles || []).map(async (profile) => {
          const { data: roleData } = await supabase
            .from('user_roles')
            .select('role')
            .eq('user_id', profile.id)
            .single();

          const { data: passwordData } = await supabase
            .from('user_passwords')
            .select('password')
            .eq('user_id', profile.id)
            .single();

          return {
            ...profile,
            role: roleData?.role || 'student',
            password: passwordData?.password || null
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
      // Note: Deleting users requires admin API which should be done via edge function
      toast.error('Chức năng xóa người dùng cần được thực hiện qua Edge Function');
      // TODO: Implement admin-delete-user edge function
    } catch (error: any) {
      toast.error('Lỗi khi xóa người dùng');
    }
  };

  const handleResetPassword = async () => {
    if (!selectedUser) return;
    
    if (newPassword.length < 8) {
      toast.error('Mật khẩu phải có ít nhất 8 ký tự');
      return;
    }

    setResetting(true);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      
      const { data, error } = await supabase.functions.invoke('admin-reset-password', {
        body: { 
          user_id: selectedUser.id,
          new_password: newPassword
        },
        headers: {
          Authorization: `Bearer ${session?.access_token}`
        }
      });

      if (error) throw error;

      toast.success(`Đã đặt lại mật khẩu cho ${selectedUser.full_name}`);
      setResetDialogOpen(false);
      setNewPassword('');
      setSelectedUser(null);
      // Refresh user list to show new password
      fetchUsers();
    } catch (error: any) {
      toast.error(error.message || 'Lỗi khi đặt lại mật khẩu');
      console.error(error);
    } finally {
      setResetting(false);
    }
  };

  const openResetDialog = (user: UserData) => {
    setSelectedUser(user);
    setNewPassword('');
    setResetDialogOpen(true);
  };

  const filteredUsers = users.filter(user =>
    user.full_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    user.email.toLowerCase().includes(searchTerm.toLowerCase())
  );

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
            <h1 className="text-3xl font-bold text-foreground mb-2">Quản lý Người dùng</h1>
            <p className="text-muted-foreground">Tổng số: {users.length} người dùng</p>
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
            <CardTitle>Danh sách Người dùng</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {filteredUsers.map((user, index) => (
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
                      {user.password && (
                        <div className="flex items-center gap-2 mt-2">
                          <p className="text-xs font-mono text-primary">
                            Mật khẩu: {showPassword[user.id] ? user.password : '••••••••'}
                          </p>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="h-5 w-5"
                            onClick={() => setShowPassword(prev => ({
                              ...prev,
                              [user.id]: !prev[user.id]
                            }))}
                          >
                            {showPassword[user.id] ? (
                              <EyeOff className="h-3 w-3" />
                            ) : (
                              <Eye className="h-3 w-3" />
                            )}
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      size="icon"
                      variant="ghost"
                      onClick={() => openResetDialog(user)}
                      title="Đặt lại mật khẩu"
                    >
                      <Key className="h-4 w-4 text-primary" />
                    </Button>
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

            {filteredUsers.length === 0 && (
              <div className="text-center py-12">
                <UsersIcon className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">Không tìm thấy người dùng</p>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      <Dialog open={resetDialogOpen} onOpenChange={setResetDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Đặt lại mật khẩu</DialogTitle>
            <DialogDescription>
              Đặt mật khẩu mới cho <strong>{selectedUser?.full_name}</strong> ({selectedUser?.email})
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="new-password">Mật khẩu mới</Label>
              <Input
                id="new-password"
                type="text"
                placeholder="Ít nhất 8 ký tự"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                autoComplete="off"
              />
              <p className="text-sm text-muted-foreground">
                Mật khẩu này sẽ được hiển thị để bạn có thể cung cấp cho người dùng
              </p>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setResetDialogOpen(false);
                setNewPassword('');
                setSelectedUser(null);
              }}
              disabled={resetting}
            >
              Hủy
            </Button>
            <Button onClick={handleResetPassword} disabled={resetting}>
              {resetting ? 'Đang xử lý...' : 'Đặt lại mật khẩu'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default Users;
