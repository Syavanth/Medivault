import { ArrowRight, Shield, FileText, Lock } from "lucide-react"
import { useNavigate } from 'react-router-dom'

export default function WelcomePage() {
  const navigate = useNavigate()
  const features = [
    {
      icon: <Shield className="w-8 h-8" />,
      title: "Secure Storage",
      description: "Your medical records are encrypted and stored with bank-level security"
    },
    {
      icon: <FileText className="w-8 h-8" />,
      title: "Easy Access",
      description: "Retrieve your health information anytime, anywhere"
    },
    {
      icon: <Lock className="w-8 h-8" />,
      title: "Privacy Control",
      description: "You decide who can access your medical data"
    }
  ]

  const handleGetStartedClick = () => {
    navigate('/auth')
  }

  return (
    <div className="h-screen flex flex-col items-center justify-center p-4 bg-white overflow-hidden">
      <div className="w-full max-w-4xl space-y-8">
        {/* Welcome Section */}
        <div className="text-center space-y-4">
          <h1 className="text-4xl md:text-5xl font-bold text-black">
            Welcome to Medivault
          </h1>
          <p className="text-xl text-gray-700 max-w-2xl mx-auto">
            Your personal health records, secured and accessible whenever you need them
          </p>
          <button 
            onClick={handleGetStartedClick}
            className="mt-6 px-6 py-3 text-lg bg-[#30C0B0] hover:bg-[#20A090] text-white rounded-lg flex items-center mx-auto"
          >
            Get Started <ArrowRight className="ml-2 h-5 w-5" />
          </button>
        </div>

        {/* Features Section */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {features.map((feature, index) => (
            <div key={index} className="p-4 border border-gray-200 rounded-lg hover:shadow-lg transition-shadow">
              <div className="flex flex-col items-center">
                <div className="text-[#30C0B0]">
                  {feature.icon}
                </div>
                <h3 className="text-xl font-semibold text-black mt-2">{feature.title}</h3>
                <p className="text-center text-gray-700 text-sm">
                  {feature.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}


