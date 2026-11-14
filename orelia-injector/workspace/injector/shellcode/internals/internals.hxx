#pragma once

namespace shellcode {
	class c_shellcode {
	public:
		c_shellcode( std::uint64_t dll_main ) :
			m_entry_point( dll_main ), m_reflective_mode( false ) {
		}

		c_shellcode( std::uint64_t reflective_loader, reflective::reflective_data_t reflective_data ) :
			m_entry_point( reflective_loader ), m_reflective_data( reflective_data ), m_reflective_mode( true ) {
		}

		bool setup( ) {
			auto graphicshook64 = g_driver->get_process_module( encrypt( L"graphics-hook64.dll" ) );
			if ( !graphicshook64 ) {
				logging::print( encrypt( "Please install or launch OBS Studios and start capture for the process." ) );
				return false;
			}

			this->m_inject_address = graphicshook64 + 0x42DC8;
			this->m_original_fn = g_driver->read( m_inject_address );
			if ( !m_original_fn ) {
				logging::print( encrypt( "Failed to get VTable." ) );
				return false;
			}

			if ( m_reflective_mode ) {
				this->m_reflective_data_va = g_driver->allocate_virtual( sizeof( m_reflective_data ) );
				if ( !m_reflective_data_va ) {
					logging::print( encrypt( "Failed to allocate reflective data" ) );
					return false;
				}

				if ( !g_driver->write_memory( m_reflective_data_va, &m_reflective_data, sizeof( m_reflective_data ) ) ) {
					logging::print( encrypt( "Failed to create reflective context" ) );
					return false;
				}
			}

			return true;
		}

		bool update( ) {
			auto compiler = std::make_unique<compiler::c_compiler>( );
			compiler->setup( );
			compiler->setup_registers( );
			compiler->add_random_nops( );

			compiler->store_data( );
			compiler->check_status( );
			compiler->add_random_nops( );

			compiler->set_status( 1 );

			if ( m_reflective_mode ) {
				compiler->set_rcx( m_reflective_data_va );
			}
			else {
				compiler->set_rcx( g_driver->m_base_address );
				compiler->set_rdx( DLL_PROCESS_ATTACH );
			}

			compiler->add_random_nops( );

			compiler->set_status( 2 );
			compiler->create_frame( );
			compiler->set_rax( m_entry_point );
			compiler->call_rax( );
			compiler->restore_frame( );
			compiler->add_random_nops( );

			compiler->store_return( );
			compiler->set_status( 3 );
			compiler->add_random_nops( );

			compiler->bind_execution_skip( );
			compiler->restore_registers( );
			compiler->add_random_nops( );

			compiler->set_rax( m_original_fn );
			compiler->jmp_rax( );

			if ( !compiler->set_data_ref( &m_data_va ) ) {
				logging::print( encrypt( "Failed to generate xrefs." ) );
				return false;
			}

			if ( !compiler->generate( &m_shellcode_va ) ) {
				logging::print( encrypt( "Failed to generate shellcode." ) );
				return false;
			}

			logging::print( encrypt( "Shellcode initialization complete:" ) );
			logging::print( encrypt( "  - Inject address: 0x%llX" ), m_inject_address );

			if ( m_reflective_mode ) {
				logging::print( encrypt( "  - Reflective data: 0x%llX" ), m_reflective_data_va );
			}

			logging::print( encrypt( "  - Entrypoint: 0x%llX" ), m_entry_point );
			logging::print( encrypt( "Successfully initializated shellcode\n" ) );
			return true;
		}

		bool run( ) {
			logging::print( encrypt( "Waiting for module initialization" ) );

			g_driver->write( m_inject_address, m_shellcode_va );

			while ( true ) {
				if ( !g_driver->get_process_id( target_process ) ) {
					debug_exception( );
					return false;
				}

				if ( m_reflective_mode ) {
					g_driver->read_memory( m_reflective_data_va, &m_reflective_data, sizeof( m_reflective_data ) );
				}

				g_driver->read_memory( m_data_va, &m_remote_data, sizeof( m_remote_data ) );
				if ( m_remote_data.m_status == 3 )
					break;

				std::this_thread::sleep_for(
					std::chrono::milliseconds(
					25
				) );
			}

			logging::print( encrypt( "Module initialization complete:" ) );
			logging::print( encrypt( "  - Shellcode Status: %i" ), m_remote_data.m_status );

			if ( m_reflective_mode ) {
				logging::print( encrypt( "  - Reflective Return: %i" ), m_remote_data.m_return );
				logging::print( encrypt( "  - DllMain Return: %i" ), m_reflective_data.m_dll_return );
			}
			else {
				logging::print( encrypt( "  - Shellcode Return: %i" ), m_remote_data.m_return );
			}

			logging::print( encrypt( "Successfully initialized module\n" ) );
			return true;
		}

		void cleanup( ) const {
			if ( m_inject_address && m_original_fn )
				g_driver->write( m_inject_address, m_original_fn );

			if ( m_data_va ) g_driver->free_virtual( m_data_va );
			if ( m_shellcode_va ) g_driver->free_virtual( m_shellcode_va );
			if ( m_reflective_data_va ) g_driver->free_virtual( m_reflective_data_va );
		}

	private:
		std::uint64_t m_data_va = 0;
		std::uint64_t m_shellcode_va = 0;
		std::uint64_t m_inject_address = 0;
		std::uint64_t m_original_fn = 0;
		std::uint64_t m_entry_point = 0;
		std::uint64_t m_reflective_data_va = 0;
		bool m_reflective_mode = false;
		shellcode::inject_data_t m_remote_data{};
		reflective::reflective_data_t m_reflective_data{};

		void debug_exception( ) const {
			switch ( m_remote_data.m_status ) {
			case 1:
			{
				logging::print( encrypt( "Target process terminated unexpectedly during module preperation" ) );
			} break;
			case 2:
			{
				logging::print( encrypt( "Target process terminated unexpectedly during execution in RAX" ) );
				logging::print( encrypt( "Exception likely due to corrupted module code." ) );
			} break;
			case 3:
			{
				logging::print( encrypt( "Target process terminated unexpectedly during cleanup" ) );
				logging::print( encrypt( "Exception likely due to corrupted stack frame." ) );
			} break;
			default:
			{
				logging::print( encrypt( "Target process terminated unexpectedly" ) );
			} break;
			}

			if ( m_reflective_mode ) {
				if ( m_remote_data.m_return || m_reflective_data.m_dll_return )
					logging::print( encrypt( "Shellcode Exception Data, Shellcode Return=%i, Reflective Return=%i" ),
						m_remote_data.m_return, m_reflective_data.m_dll_return );
			}
			else {
				if ( m_remote_data.m_return )
					logging::print( encrypt( "Shellcode Exception Data, Shellcode Return=%i" ),
						m_remote_data.m_return );
			}
		}
	};
}